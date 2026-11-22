#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Sigyll.Common.Services.Pqc;

namespace Sigyll.Common.Services;

public enum DetectedCertRole
{
    RootCa,
    IntermediateCa,
    EndEntity
}

public class ParsedCertificate
{
    public X509Certificate2 Certificate { get; set; } = null!;
    public byte[] RawFileBytes { get; set; } = [];
    public string FileName { get; set; } = string.Empty;
    public DetectedCertRole DetectedRole { get; set; }
    public string? SubjectKeyIdentifier { get; set; }
    public string? AuthorityKeyIdentifier { get; set; }
    public string? SubjectAltNames { get; set; }
    public string Algorithm { get; set; } = "Unknown";
    public int KeySize { get; set; }
    public bool HasPrivateKey { get; set; }
}

public class CertificateParsingService
{
    /// <summary>
    /// Parses a certificate file (.pfx, .cer, .pem) and returns structured info.
    /// </summary>
    public ParsedCertificate? Parse(byte[] fileBytes, string fileName, string? password = null)
    {
        X509Certificate2? cert = null;
        var ext = Path.GetExtension(fileName).ToLowerInvariant();

        try
        {
            if (ext == ".pfx" || ext == ".p12")
            {
                cert = X509CertificateLoader.LoadPkcs12(fileBytes, password,
                    X509KeyStorageFlags.Exportable);
            }
            else if (ext is ".cer" or ".crt" or ".der" or ".pem")
            {
                // Try DER first, then PEM
                try
                {
                    cert = X509CertificateLoader.LoadCertificate(fileBytes);
                }
                catch
                {
                    var pem = System.Text.Encoding.UTF8.GetString(fileBytes);
                    cert = X509Certificate2.CreateFromPem(pem);
                }
            }
            else
            {
                // Try PEM first, then DER
                try
                {
                    cert = X509CertificateLoader.LoadCertificate(fileBytes);
                }
                catch
                {
                    cert = X509CertificateLoader.LoadPkcs12(fileBytes, password,
                        X509KeyStorageFlags.Exportable);
                }
            }
        }
        catch
        {
            return null;
        }

        if (cert == null) return null;

        return Describe(cert, fileBytes, fileName);
    }

    /// <summary>
    /// The CA certificates a PKCS #12 file carries besides the certificate its private key belongs to, each
    /// issuer before the certificates it issued. Empty when the file holds none, or can't be read as PKCS #12
    /// with this password.
    /// </summary>
    public static IReadOnlyList<ParsedCertificate> ParseCaChain(byte[] fileBytes, string fileName, string? password)
    {
        X509Certificate2Collection all;
        try
        {
            all = X509CertificateLoader.LoadPkcs12Collection(fileBytes, password, Pkcs12KeyStorage.InMemory);
        }
        catch (Exception)
        {
            return [];
        }

        var cas = new List<ParsedCertificate>();
        foreach (var cert in all)
        {
            if (cert.HasPrivateKey || DetectRole(cert) == DetectedCertRole.EndEntity)
            {
                cert.Dispose();
                continue;
            }

            // Without its key, the certificate is stored as it would be from a .cer file.
            cas.Add(Describe(cert, cert.RawData, fileName));
        }

        // Roots first, then each certificate after its issuer, so an intermediate finds its parent already imported.
        var ordered = new List<ParsedCertificate>();
        var remaining = cas.OrderBy(c => c.DetectedRole == DetectedCertRole.RootCa ? 0 : 1).ToList();
        while (remaining.Count > 0)
        {
            var next = remaining.FirstOrDefault(c => c.DetectedRole == DetectedCertRole.RootCa
                    || remaining.All(other => other == c || other.Certificate.Subject != c.Certificate.Issuer))
                ?? remaining[0];
            remaining.Remove(next);
            ordered.Add(next);
        }

        return ordered;
    }

    private static ParsedCertificate Describe(X509Certificate2 cert, byte[] fileBytes, string fileName)
    {
        var (algorithm, keySize) = GetKeyInfo(cert);

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = fileBytes,
            FileName = fileName,
            DetectedRole = DetectRole(cert),
            SubjectKeyIdentifier = GetSubjectKeyIdentifier(cert),
            AuthorityKeyIdentifier = GetAuthorityKeyIdentifier(cert),
            SubjectAltNames = GetSubjectAltNames(cert),
            Algorithm = algorithm,
            KeySize = keySize,
            HasPrivateKey = cert.HasPrivateKey
        };
    }

    private static DetectedCertRole DetectRole(X509Certificate2 cert)
    {
        var bcExt = cert.Extensions["2.5.29.19"]; // BasicConstraints
        if (bcExt != null)
        {
            var bc = new X509BasicConstraintsExtension(bcExt, bcExt.Critical);
            if (bc.CertificateAuthority)
            {
                // Self-signed = root, otherwise intermediate
                return cert.Subject == cert.Issuer
                    ? DetectedCertRole.RootCa
                    : DetectedCertRole.IntermediateCa;
            }
        }

        return DetectedCertRole.EndEntity;
    }

    private static string? GetSubjectKeyIdentifier(X509Certificate2 cert)
    {
        var skiExt = cert.Extensions["2.5.29.14"];
        if (skiExt == null) return null;
        var ski = new X509SubjectKeyIdentifierExtension(skiExt, skiExt.Critical);
        return ski.SubjectKeyIdentifier;
    }

    private static string? GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        var akiExt = cert.Extensions["2.5.29.35"];
        if (akiExt?.RawData == null || akiExt.RawData.Length < 6) return null;

        try
        {
            var data = akiExt.RawData;
            int offset = 2; // skip SEQUENCE tag + length
            if (data[offset] == 0x80) // [0] implicit tag
            {
                var len = data[offset + 1];
                var keyId = new byte[len];
                Array.Copy(data, offset + 2, keyId, 0, len);
                return Convert.ToHexString(keyId);
            }
        }
        catch { }

        return null;
    }

    private static string? GetSubjectAltNames(X509Certificate2 cert)
    {
        var sanExt = cert.Extensions["2.5.29.17"];
        if (sanExt == null) return null;

        var lines = SubjectAltNameText.Describe(sanExt);
        return lines.Count > 0 ? string.Join("; ", lines) : null;
    }

    private static (string algorithm, int keySize) GetKeyInfo(X509Certificate2 cert)
    {
        return PqcAlgorithms.DescribeCertificate(cert);
    }
}
