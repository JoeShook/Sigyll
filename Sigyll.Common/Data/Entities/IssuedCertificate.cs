#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Data.Entities;

public class IssuedCertificate
{
    public int Id { get; set; }

    public int IssuingCaCertificateId { get; set; }
    public CaCertificate IssuingCaCertificate { get; set; } = null!;

    public int? TemplateId { get; set; }
    public CertificateTemplate? Template { get; set; }

    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string? SubjectAltNames { get; set; }
    public string X509CertificatePem { get; set; } = string.Empty;
    public byte[]? EncryptedPfxBytes { get; set; }
    public string? PfxPassword { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 2048;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public int RevocationReason { get; set; }

    /// <summary>
    /// 1-based renewal generation within this certificate's lineage. Incremented each time
    /// the certificate is re-keyed (renewed); the first issuance is version 1.
    /// </summary>
    public int Version { get; set; } = 1;

    /// <summary>
    /// The certificate this one was renewed from (its direct predecessor), or null for the
    /// first issuance. Basis for renewal lineage and future ACME ARI "replaces" support.
    /// </summary>
    public int? RenewalOfId { get; set; }
    public IssuedCertificate? RenewalOf { get; set; }
    public CertSecurityLevel CertSecurityLevel { get; set; } = CertSecurityLevel.Software;
    public string? StoreProviderHint { get; set; }
    public bool Enabled { get; set; } = true;
    public bool AutoRenew { get; set; } = true;
    public bool IsArchived { get; set; }
    public DateTime? ArchivedAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
