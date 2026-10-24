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

public class TrustDomain
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    public int CrlValidityDays { get; set; } = 7;

    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Folder under the Vault KV mount that this trust domain's certificates are exported to, e.g. "team-a".
    /// Set by the first export to Vault; after that only an Admin changes it.
    /// </summary>
    public string? VaultNamespace { get; set; }

    /// <summary>Whether operators can back up the whole trust domain to its Vault namespace in one go.</summary>
    public bool VaultBackupEnabled { get; set; }

    /// <summary>When the last full backup to Vault wrote at least one secret (UTC), and who ran it.</summary>
    public DateTime? VaultLastBackupAt { get; set; }
    public string? VaultLastBackupBy { get; set; }

    public ICollection<TrustDomainBaseUrl> BaseUrls { get; set; } = new List<TrustDomainBaseUrl>();
    public ICollection<CaCertificate> CaCertificates { get; set; } = new List<CaCertificate>();
    public ICollection<DidDocument> DidDocuments { get; set; } = new List<DidDocument>();
    public ICollection<IssuedCredential> IssuedCredentials { get; set; } = new List<IssuedCredential>();
}
