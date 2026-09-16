#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Sigyll.Common.Services;

/// <summary>Outcome of <see cref="Pkcs12BundleService.Assemble"/>.</summary>
public class Pkcs12BundleResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>The PKCS#12 bundle, protected with the password supplied by the operator.</summary>
    public byte[]? Pkcs12Bytes { get; set; }

    public string SuggestedFileName { get; set; } = "certificate.p12";

    public string? Subject { get; set; }
    public string? Issuer { get; set; }
    public string? Thumbprint { get; set; }
    public string? SerialNumber { get; set; }
    public DateTime NotAfter { get; set; }
    public string KeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }

    /// <summary>DER-encoded chain certificates that were bundled alongside the leaf (issuer first when known).</summary>
    public List<byte[]> ChainDer { get; set; } = [];

    public static Pkcs12BundleResult Failure(string error) => new() { Success = false, Error = error };
}

/// <summary>
/// Joins a CA-signed certificate with the private key that produced its CSR into a PKCS#12
/// bundle. Completes the stand-alone CSR flow: CSR + .key go out, signed certificate comes back,
/// and this turns the pair into a .p12 the operator can install or import. Works entirely in
/// memory — nothing is stored and no issuing CA needs to be known to Sigyll.
/// </summary>
public class Pkcs12BundleService
{
    private readonly ILogger<Pkcs12BundleService> _logger;

    public Pkcs12BundleService(ILogger<Pkcs12BundleService> logger)
    {
        _logger = logger;
    }

    /// <param name="certificateFile">The signed certificate: DER, PEM (may contain the chain too), or PKCS#7.</param>
    /// <param name="certificateFileName">Used only for error messages and the suggested output name.</param>
    /// <param name="privateKeyPem">PKCS#8 private key PEM — encrypted (the .key Sigyll produced) or plain.</param>
    /// <param name="keyPassphrase">Passphrase for an encrypted key; ignored for a plain key.</param>
    /// <param name="chainFiles">Optional additional certificates (intermediates/root) in DER, PEM or PKCS#7.</param>
    /// <param name="p12Password">Password protecting the resulting PKCS#12.</param>
    /// <param name="name">Friendly name for the output file; defaults to the certificate's CN.</param>
    public Pkcs12BundleResult Assemble(
        byte[] certificateFile,
        string certificateFileName,
        string privateKeyPem,
        string? keyPassphrase,
        IReadOnlyList<byte[]> chainFiles,
        string p12Password,
        string? name = null)
    {
        if (certificateFile.Length == 0)
            return Pkcs12BundleResult.Failure("No signed certificate was provided.");
        if (string.IsNullOrWhiteSpace(privateKeyPem))
            return Pkcs12BundleResult.Failure("No private key was provided.");
        if (string.IsNullOrEmpty(p12Password))
            return Pkcs12BundleResult.Failure("A password for the new .p12 is required.");

        var candidates = new X509Certificate2Collection();
        var chain = new X509Certificate2Collection();
        AsymmetricAlgorithm? key = null;
        X509Certificate2? leafWithKey = null;

        try
        {
            // --- Certificates supplied in the "signed certificate" file (leaf, possibly with chain) ---
            try
            {
                candidates.AddRange(LoadCertificates(certificateFile));
            }
            catch (Exception ex)
            {
                return Pkcs12BundleResult.Failure($"Could not read '{certificateFileName}' as a certificate: {ex.Message}");
            }
            if (candidates.Count == 0)
                return Pkcs12BundleResult.Failure($"'{certificateFileName}' contains no certificates.");

            // --- Private key ---
            try
            {
                key = LoadPrivateKey(privateKeyPem, keyPassphrase);
            }
            catch (CryptographicException ex)
            {
                return Pkcs12BundleResult.Failure(IsEncrypted(privateKeyPem)
                    ? "Could not decrypt the private key — check the passphrase."
                    : $"Could not read the private key: {ex.Message}");
            }
            catch (Exception ex)
            {
                return Pkcs12BundleResult.Failure($"Could not read the private key: {ex.Message}");
            }

            // --- Find the certificate this key belongs to ---
            var keySpki = key.ExportSubjectPublicKeyInfo();
            X509Certificate2? leaf = null;
            foreach (var c in candidates)
            {
                if (c.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(keySpki))
                {
                    leaf = c;
                    break;
                }
            }

            if (leaf == null)
            {
                var described = candidates.Count == 1
                    ? $"'{candidates[0].Subject}'"
                    : $"any of the {candidates.Count} certificates in '{certificateFileName}'";
                return Pkcs12BundleResult.Failure(
                    $"The private key does not match the public key of {described}. " +
                    "Make sure this is the .key that was downloaded with the CSR the CA signed.");
            }

            // --- Chain: everything else in the certificate file plus any extra files ---
            foreach (var c in candidates)
                if (!ReferenceEquals(c, leaf)) AddUnique(chain, c, leaf);

            foreach (var file in chainFiles)
            {
                if (file.Length == 0) continue;
                try
                {
                    foreach (var c in LoadCertificates(file)) AddUnique(chain, c, leaf);
                }
                catch (Exception ex)
                {
                    return Pkcs12BundleResult.Failure($"Could not read a chain file as certificates: {ex.Message}");
                }
            }

            // --- Bundle ---
            leafWithKey = key switch
            {
                RSA rsa => leaf.CopyWithPrivateKey(rsa),
                ECDsa ecdsa => leaf.CopyWithPrivateKey(ecdsa),
                _ => throw new InvalidOperationException("Unsupported key algorithm.")
            };

            var collection = new X509Certificate2Collection { leafWithKey };
            collection.AddRange(OrderChain(chain, leaf).ToArray());

            var p12 = collection.Export(X509ContentType.Pkcs12, p12Password);
            if (p12 == null || p12.Length == 0)
                return Pkcs12BundleResult.Failure("PKCS#12 export produced no data.");

            var (alg, size) = key switch
            {
                RSA r => ("RSA", r.KeySize),
                ECDsa e => ("ECDSA", e.KeySize),
                _ => ("Unknown", 0)
            };

            var baseName = string.IsNullOrWhiteSpace(name)
                ? leaf.GetNameInfo(X509NameType.SimpleName, false)
                : name.Trim();

            _logger.LogInformation(
                "Assembled PKCS#12 for '{Subject}' ({Alg} {Size}) with {ChainCount} chain certificate(s)",
                leaf.Subject, alg, size, chain.Count);

            return new Pkcs12BundleResult
            {
                Success = true,
                Pkcs12Bytes = p12,
                SuggestedFileName = SanitizeFileName(baseName) + ".p12",
                Subject = leaf.Subject,
                Issuer = leaf.Issuer,
                Thumbprint = leaf.Thumbprint,
                SerialNumber = leaf.SerialNumber,
                NotAfter = leaf.NotAfter.ToUniversalTime(),
                KeyAlgorithm = alg,
                KeySize = size,
                ChainDer = OrderChain(chain, leaf).Select(c => c.RawData).ToList()
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PKCS#12 assembly failed for '{File}'", certificateFileName);
            return Pkcs12BundleResult.Failure($"PKCS#12 assembly failed: {ex.Message}");
        }
        finally
        {
            key?.Dispose();
            leafWithKey?.Dispose();
            foreach (var c in candidates) c.Dispose();
            foreach (var c in chain) c.Dispose();
        }
    }

    /// <summary>Loads one or more certificates from DER, PEM (multi-cert) or PKCS#7 bytes.</summary>
    private static X509Certificate2Collection LoadCertificates(byte[] bytes)
    {
        var result = new X509Certificate2Collection();

        var text = TryDecodeText(bytes);
        if (text != null && text.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            // Plain CERTIFICATE blocks (possibly several — a PEM chain)
            if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                result.ImportFromPem(text);

            // PEM-armored PKCS#7 / CMS (what many CAs hand out as .p7b): decode each block and
            // let BouncyCastle unwrap the SignedData certificate bag
            foreach (var (label, der) in EnumeratePemBlocks(text))
            {
                if (label is not ("PKCS7" or "CMS")) continue;
                foreach (var bc in new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificates(der))
                    result.Add(X509CertificateLoader.LoadCertificate(bc.GetEncoded()));
            }

            if (result.Count == 0)
                throw new CryptographicException("The PEM file contains no CERTIFICATE or PKCS7 blocks.");
            return result;
        }

        try
        {
            result.Add(X509CertificateLoader.LoadCertificate(bytes));
            return result;
        }
        catch (CryptographicException)
        {
            // Not a single DER certificate — try PKCS#7 (.p7b) via BouncyCastle, which unwraps SignedData cert bags
        }

        foreach (var bc in new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificates(bytes))
            result.Add(X509CertificateLoader.LoadCertificate(bc.GetEncoded()));

        if (result.Count == 0)
            throw new CryptographicException("No certificates found (expected DER, PEM or PKCS#7).");
        return result;
    }

    private static AsymmetricAlgorithm LoadPrivateKey(string pem, string? passphrase)
    {
        var encrypted = IsEncrypted(pem);
        if (encrypted && string.IsNullOrEmpty(passphrase))
            throw new CryptographicException("The private key is encrypted; a passphrase is required.");

        // Try RSA first, then ECDSA — the PEM does not say which until parsed.
        var rsa = RSA.Create();
        try
        {
            if (encrypted) rsa.ImportFromEncryptedPem(pem, passphrase!);
            else rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
        try
        {
            if (encrypted) ecdsa.ImportFromEncryptedPem(pem, passphrase!);
            else ecdsa.ImportFromPem(pem);
            return ecdsa;
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    /// <summary>Yields every (label, DER bytes) PEM block in the text, in order.</summary>
    private static IEnumerable<(string Label, byte[] Der)> EnumeratePemBlocks(string text)
    {
        var remaining = text.AsMemory();
        while (PemEncoding.TryFind(remaining.Span, out var fields))
        {
            var label = remaining.Span[fields.Label].ToString();
            var base64 = remaining.Span[fields.Base64Data];
            var der = new byte[fields.DecodedDataLength];
            if (Convert.TryFromBase64Chars(base64, der, out var written))
                yield return (label, written == der.Length ? der : der[..written]);

            remaining = remaining[fields.Location.End..];
        }
    }

    private static bool IsEncrypted(string pem) =>
        pem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal);

    private static string? TryDecodeText(byte[] bytes)
    {
        // PEM is ASCII; a DER blob almost always starts with 0x30 and contains bytes > 0x7F.
        if (bytes.Length == 0 || bytes[0] == 0x30) return null;
        try
        {
            var text = Encoding.ASCII.GetString(bytes);
            return text.Any(ch => ch == '�' || (ch < ' ' && ch is not ('\r' or '\n' or '\t'))) ? null : text;
        }
        catch
        {
            return null;
        }
    }

    private static void AddUnique(X509Certificate2Collection chain, X509Certificate2 cert, X509Certificate2 leaf)
    {
        if (string.Equals(cert.Thumbprint, leaf.Thumbprint, StringComparison.OrdinalIgnoreCase)) return;
        foreach (var existing in chain)
            if (string.Equals(existing.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase)) return;
        chain.Add(cert);
    }

    /// <summary>Orders chain certificates issuer-first by following Issuer → Subject links; unmatched ones keep their order at the end.</summary>
    private static List<X509Certificate2> OrderChain(X509Certificate2Collection chain, X509Certificate2 leaf)
    {
        var remaining = chain.Cast<X509Certificate2>().ToList();
        var ordered = new List<X509Certificate2>();
        var current = leaf;

        while (remaining.Count > 0)
        {
            var next = remaining.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData)
                                                     && !ReferenceEquals(c, current));
            if (next == null) break;
            ordered.Add(next);
            remaining.Remove(next);
            if (next.SubjectName.RawData.AsSpan().SequenceEqual(next.IssuerName.RawData)) break; // reached a root
            current = next;
        }

        ordered.AddRange(remaining);
        return ordered;
    }

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Trim().Select(c => invalid.Contains(c) || c == ' ' ? '-' : c).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "certificate" : cleaned;
    }
}
