#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.ViewModels;

/// <summary>
/// How the key pair for a generated PKCS#10 CSR is chosen.
/// </summary>
public enum CsrKeyMode
{
    /// <summary>Sign the CSR with the selected certificate's existing private key (renewal without re-key).</summary>
    ReuseExistingKey,

    /// <summary>Generate a fresh key pair; the private key is returned encrypted for the operator to keep.</summary>
    GenerateNewKey
}

/// <summary>
/// Request to build a PKCS#10 Certificate Signing Request modeled on an existing certificate
/// held in Sigyll. Used when an external CA issued the original certificate and now expects a
/// CSR for renewal instead of issuing a replacement on its own.
/// </summary>
public class CsrGenerationRequest
{
    /// <summary>The certificate the CSR is modeled on.</summary>
    public int CertificateId { get; set; }

    /// <summary>"CaCertificate" or "IssuedCertificate".</summary>
    public string EntityType { get; set; } = "IssuedCertificate";

    public CsrKeyMode KeyMode { get; set; } = CsrKeyMode.ReuseExistingKey;

    /// <summary>"RSA" or "ECDSA" — only used when <see cref="KeyMode"/> is GenerateNewKey.</summary>
    public string NewKeyAlgorithm { get; set; } = "RSA";

    /// <summary>RSA modulus bits (2048/3072/4096) or ECDSA curve size (256/384/521).</summary>
    public int NewKeySize { get; set; } = 2048;

    /// <summary>
    /// Passphrase protecting the returned PKCS#8 private key. Required when generating a new key,
    /// because the key is handed back to the operator rather than stored.
    /// </summary>
    public string? NewKeyPassphrase { get; set; }

    /// <summary>Subject DN for the CSR. Null keeps the existing certificate's subject, encoding intact.</summary>
    public string? SubjectDn { get; set; }

    /// <summary>
    /// SANs to request. Null copies the existing certificate's SAN extension verbatim;
    /// an empty list omits SANs entirely.
    /// </summary>
    public List<SanEntry>? SubjectAltNames { get; set; }

    /// <summary>
    /// Copy Key Usage, Extended Key Usage and Basic Constraints from the existing certificate
    /// into the CSR's requested extensions. Most CAs apply their own profile, but including them
    /// tells the CA what the original certificate looked like.
    /// </summary>
    public bool IncludeExistingExtensions { get; set; } = true;
}

/// <summary>
/// Result of <see cref="CsrGenerationRequest"/>: the PEM CSR plus, for a new key, the encrypted key.
/// </summary>
public class CsrGenerationResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>PEM-encoded PKCS#10 request ("-----BEGIN CERTIFICATE REQUEST-----").</summary>
    public string? CsrPem { get; set; }

    /// <summary>Subject DN as placed in the CSR.</summary>
    public string? SubjectDn { get; set; }

    public string KeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }

    /// <summary>SHA-256 over the SubjectPublicKeyInfo, hex. Lets the operator match the returned certificate to this request.</summary>
    public string? PublicKeyThumbprint { get; set; }

    /// <summary>Only set for GenerateNewKey: PKCS#8 private key, PEM, encrypted with the supplied passphrase.</summary>
    public string? EncryptedPrivateKeyPem { get; set; }

    /// <summary>File name suggestion for the .csr download, derived from the certificate name.</summary>
    public string SuggestedFileName { get; set; } = "request.csr";

    public static CsrGenerationResult Failure(string error) => new() { Success = false, Error = error };
}
