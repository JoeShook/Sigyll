#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Portal.Data.Entities;

/// <summary>
/// An organization a requester can act on behalf of. Org vetting (domain control + business
/// validation) is what authorizes members to request under specific trust domains; the policy
/// engine uses membership to decide auto-issue vs. RA approval.
/// </summary>
public class Organization
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;

    /// <summary>Semicolon-delimited DNS domains this org has been validated to control.</summary>
    public string? ValidatedDomains { get; set; }

    /// <summary>Semicolon-delimited trust-domain names this org is authorized to request under.</summary>
    public string? AuthorizedTrustDomains { get; set; }

    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<OrganizationMembership> Memberships { get; set; } = new List<OrganizationMembership>();
}
