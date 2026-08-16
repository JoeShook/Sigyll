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

public enum CertSecurityLevel : byte
{
    Software = 0,
    Fips1403 = 1,
    CloudKms = 2
}

public class CaCertificate
{
    public int Id { get; set; }

    public int TrustDomainId { get; set; }
    public TrustDomain TrustDomain { get; set; } = null!;

    /// <summary>
    /// Null for root CAs; set for intermediates pointing to their issuing CA.
    /// </summary>
    public int? ParentId { get; set; }
    public CaCertificate? Parent { get; set; }

    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string X509CertificatePem { get; set; } = string.Empty;
    public byte[]? EncryptedPfxBytes { get; set; }
    public string? PfxPassword { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 4096;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string? CrlDistributionPoint { get; set; }
    public string? AuthorityInfoAccessUri { get; set; }
    public CertSecurityLevel CertSecurityLevel { get; set; } = CertSecurityLevel.Software;
    public string? StoreProviderHint { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime? RevokedAt { get; set; }
    public int RevocationReason { get; set; }

    /// <summary>
    /// 1-based renewal generation within this CA's lineage. Incremented each time the CA
    /// is re-keyed (renewed); the first issuance is version 1.
    /// </summary>
    public int Version { get; set; } = 1;

    /// <summary>
    /// The CA certificate this one was renewed from (its direct predecessor), or null for
    /// the first issuance.
    /// </summary>
    public int? RenewalOfId { get; set; }
    public CaCertificate? RenewalOf { get; set; }
    public bool Enabled { get; set; } = true;
    public bool AutoRenew { get; set; } = true;
    public bool IsArchived { get; set; }
    public DateTime? ArchivedAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsRootCa => ParentId == null;

    public ICollection<CaCertificate> Children { get; set; } = new List<CaCertificate>();
    public ICollection<IssuedCertificate> IssuedCertificates { get; set; } = new List<IssuedCertificate>();
    public ICollection<Crl> Crls { get; set; } = new List<Crl>();
}
