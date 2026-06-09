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
/// Links a <see cref="PortalUser"/> to an <see cref="Organization"/> with an org-scoped role.
/// Distinct from the application roles (Requester / RA / PortalAdmin), which govern portal features.
/// </summary>
public class OrganizationMembership
{
    public int Id { get; set; }

    public int OrganizationId { get; set; }
    public Organization Organization { get; set; } = null!;

    /// <summary>Identity user id (PortalUser.Id is a string).</summary>
    public string UserId { get; set; } = string.Empty;

    public MembershipRole Role { get; set; } = MembershipRole.Member;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>Org-scoped role for a membership.</summary>
public enum MembershipRole
{
    Member = 0,
    Admin = 1,
}
