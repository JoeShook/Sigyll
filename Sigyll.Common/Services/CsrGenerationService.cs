#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.ViewModels;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigyll.Common.Services;

/// <summary>
/// Builds PKCS#10 Certificate Signing Requests modeled on an existing certificate. The typical
/// case is a certificate issued by an external CA where that CA now requires a CSR for renewal.
/// The CSR reproduces the certificate's subject, SANs and requested extensions and is signed
/// either by the existing key or by a freshly generated one.
///
/// Two entry points: <see cref="GenerateCsrAsync"/> works on a certificate stored in Sigyll;
/// <see cref="GenerateCsrFromCertificate"/> works on any in-memory certificate (e.g. a .p12 the
/// operator just uploaded) and touches neither the database nor any CA.
/// </summary>
public class CsrGenerationService
{
    private const string SanOid = "2.5.29.17";
    private const string KeyUsageOid = "2.5.29.15";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string BasicConstraintsOid = "2.5.29.19";

    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly ILogger<CsrGenerationService> _logger;

    public CsrGenerationService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        ILogger<CsrGenerationService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    /// <summary>Generates a CSR modeled on a certificate stored in Sigyll (CA or issued).</summary>
    public async Task<CsrGenerationResult> GenerateCsrAsync(CsrGenerationRequest request, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        string name;
        string? pem;
        byte[]? pfxBytes;
        string? pfxPassword;
        string? storeProviderHint;
        CertSecurityLevel securityLevel;

        if (request.EntityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([request.CertificateId], ct);
            if (ca == null) return CsrGenerationResult.Failure("Certificate not found.");
            (name, pem, pfxBytes, pfxPassword, storeProviderHint, securityLevel) =
                (ca.Name, ca.X509CertificatePem, ca.EncryptedPfxBytes, ca.PfxPassword, ca.StoreProviderHint, ca.CertSecurityLevel);
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([request.CertificateId], ct);
            if (issued == null) return CsrGenerationResult.Failure("Certificate not found.");
            (name, pem, pfxBytes, pfxPassword, storeProviderHint, securityLevel) =
                (issued.Name, issued.X509CertificatePem, issued.EncryptedPfxBytes, issued.PfxPassword, issued.StoreProviderHint, issued.CertSecurityLevel);
        }

        if (string.IsNullOrWhiteSpace(pem))
            return CsrGenerationResult.Failure("Certificate has no stored public certificate to model the CSR on.");

        X509Certificate2 model;
        try
        {
            if (request.KeyMode == CsrKeyMode.ReuseExistingKey)
            {
                if (!string.IsNullOrEmpty(storeProviderHint))
                    return CsrGenerationResult.Failure(
                        "This certificate's key lives in a remote signing provider. Reusing it for a CSR is not supported yet — generate a new key instead.");
                if (securityLevel != CertSecurityLevel.Software)
                    return CsrGenerationResult.Failure("The private key cannot be used outside its security boundary.");
                if (pfxBytes == null)
                    return CsrGenerationResult.Failure("No private key is stored for this certificate; generate a new key instead.");

                model = X509CertificateLoader.LoadPkcs12(pfxBytes, pfxPassword,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

                using var publicCert = X509Certificate2.CreateFromPem(pem);
                if (!string.Equals(publicCert.Thumbprint, model.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    model.Dispose();
                    return CsrGenerationResult.Failure("The stored private key bundle does not match the certificate.");
                }
            }
            else
            {
                model = X509Certificate2.CreateFromPem(pem);
            }
        }
        catch (Exception ex)
        {
            return CsrGenerationResult.Failure($"Stored certificate could not be loaded: {ex.Message}");
        }

        using (model)
        {
            return GenerateCsrFromCertificate(model, name, request);
        }
    }

    /// <summary>
    /// Generates a CSR modeled on an in-memory certificate. Nothing is read from or written to the
    /// database, and no issuing CA is required. When <see cref="CsrKeyMode.ReuseExistingKey"/> is
    /// requested the certificate must carry its private key (e.g. loaded from a .p12).
    /// </summary>
    public CsrGenerationResult GenerateCsrFromCertificate(X509Certificate2 certificate, string name, CsrGenerationRequest options)
    {
        AsymmetricAlgorithm? key = null;
        try
        {
            if (options.KeyMode == CsrKeyMode.ReuseExistingKey)
            {
                if (!certificate.HasPrivateKey)
                    return CsrGenerationResult.Failure("No private key is available for this certificate; generate a new key instead.");

                key = (AsymmetricAlgorithm?)certificate.GetRSAPrivateKey() ?? certificate.GetECDsaPrivateKey();
                if (key == null)
                    return CsrGenerationResult.Failure("Unsupported key algorithm in the private key.");
            }
            else
            {
                if (string.IsNullOrWhiteSpace(options.NewKeyPassphrase))
                    return CsrGenerationResult.Failure("A passphrase is required to protect the new private key.");

                key = CreateNewKey(options.NewKeyAlgorithm, options.NewKeySize);
            }

            var (keyAlgorithm, keySize) = DescribeKey(key);

            var subjectName = !string.IsNullOrWhiteSpace(options.SubjectDn)
                              && !string.Equals(options.SubjectDn.Trim(), certificate.Subject, StringComparison.Ordinal)
                ? new X500DistinguishedName(options.SubjectDn.Trim())
                : certificate.SubjectName; // keep the original encoding byte-for-byte

            var csr = key switch
            {
                RSA rsa => new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                ECDsa ecdsa => new CertificateRequest(subjectName, ecdsa, HashAlgorithmName.SHA256),
                _ => throw new InvalidOperationException("Unsupported key algorithm.")
            };

            AddSubjectAltNames(csr, certificate, options.SubjectAltNames);

            if (options.IncludeExistingExtensions)
            {
                foreach (var oid in new[] { KeyUsageOid, ExtendedKeyUsageOid, BasicConstraintsOid })
                {
                    var ext = certificate.Extensions[oid];
                    if (ext != null)
                        csr.CertificateExtensions.Add(new X509Extension(ext.Oid!, ext.RawData, ext.Critical));
                }
            }

            var csrPem = csr.CreateSigningRequestPem();
            var spki = csr.PublicKey.ExportSubjectPublicKeyInfo();

            var result = new CsrGenerationResult
            {
                Success = true,
                CsrPem = csrPem,
                SubjectDn = subjectName.Name,
                KeyAlgorithm = keyAlgorithm,
                KeySize = keySize,
                PublicKeyThumbprint = Convert.ToHexString(SHA256.HashData(spki)),
                SuggestedFileName = SanitizeFileName(name) + ".csr"
            };

            if (options.KeyMode == CsrKeyMode.GenerateNewKey)
            {
                var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
                result.EncryptedPrivateKeyPem = key.ExportEncryptedPkcs8PrivateKeyPem(options.NewKeyPassphrase!, pbe);
            }

            _logger.LogInformation(
                "Generated CSR modeled on '{Name}' using {KeyMode}, {KeyAlgorithm} {KeySize}",
                name, options.KeyMode, keyAlgorithm, keySize);

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CSR generation failed for '{Name}'", name);
            return CsrGenerationResult.Failure($"CSR generation failed: {ex.Message}");
        }
        finally
        {
            key?.Dispose();
        }
    }

    /// <summary>
    /// Reads the certificate's Subject Alternative Names as editable entries. Only the name forms
    /// Sigyll can rebuild (URI, DNS, email, IP) are returned; anything else (otherName etc.) is
    /// preserved only when the SAN extension is copied verbatim.
    /// </summary>
    public static List<SanEntry> ExtractSubjectAltNames(X509Certificate2 certificate)
    {
        var result = new List<SanEntry>();
        var ext = certificate.Extensions[SanOid];
        if (ext == null) return result;

        try
        {
            var names = GeneralNames.GetInstance(Asn1Object.FromByteArray(ext.RawData));
            foreach (var gn in names.GetNames())
            {
                switch (gn.TagNo)
                {
                    case GeneralName.UniformResourceIdentifier:
                        result.Add(new SanEntry(SanType.Uri, DerIA5String.GetInstance(gn.Name).GetString()));
                        break;
                    case GeneralName.DnsName:
                        result.Add(new SanEntry(SanType.Dns, DerIA5String.GetInstance(gn.Name).GetString()));
                        break;
                    case GeneralName.Rfc822Name:
                        result.Add(new SanEntry(SanType.Email, DerIA5String.GetInstance(gn.Name).GetString()));
                        break;
                    case GeneralName.IPAddress:
                        result.Add(new SanEntry(SanType.IpAddress,
                            new IPAddress(Asn1OctetString.GetInstance(gn.Name).GetOctets()).ToString()));
                        break;
                }
            }
        }
        catch
        {
            // Malformed SAN — leave the list empty; the caller can still copy the extension verbatim
        }

        return result;
    }

    private static void AddSubjectAltNames(CertificateRequest csr, X509Certificate2 existing, List<SanEntry>? sans)
    {
        if (sans == null)
        {
            // Copy the existing SAN extension verbatim — preserves otherName and any encoding quirks
            var existingSan = existing.Extensions[SanOid];
            if (existingSan != null)
                csr.CertificateExtensions.Add(new X509Extension(existingSan.Oid!, existingSan.RawData, existingSan.Critical));
            return;
        }

        // Built via BouncyCastle so the URI text is preserved exactly — .NET's builder would
        // turn "https://host" into "https://host/", which breaks UDAP base-URL matching.
        var sanExtension = SanExtensionBuilder.Build(sans);
        if (sanExtension != null)
            csr.CertificateExtensions.Add(sanExtension);
    }

    private static AsymmetricAlgorithm CreateNewKey(string algorithm, int size)
    {
        if (algorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = size switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentException($"Unsupported ECDSA key size {size}; use 256, 384 or 521.")
            };
            return ECDsa.Create(curve);
        }

        if (size is not (2048 or 3072 or 4096))
            throw new ArgumentException($"Unsupported RSA key size {size}; use 2048, 3072 or 4096.");
        return RSA.Create(size);
    }

    private static (string Algorithm, int Size) DescribeKey(AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => ("RSA", rsa.KeySize),
        ECDsa ecdsa => ("ECDSA", ecdsa.KeySize),
        _ => ("Unknown", 0)
    };

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Trim().Select(c => invalid.Contains(c) || c == ' ' ? '-' : c).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "request" : cleaned;
    }
}
