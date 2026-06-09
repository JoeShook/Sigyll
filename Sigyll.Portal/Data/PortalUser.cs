#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Identity;

namespace Sigyll.Portal.Data;

/// <summary>
/// Application user for the certificate request portal. Passkeys (WebAuthn/FIDO2) handle
/// authentication; <see cref="ProofingStatus"/> tracks the separate identity-proofing gate that
/// (later) mints the EAB credential. Organization membership scopes what a user may request.
/// </summary>
public class PortalUser : IdentityUser
{
    /// <summary>Friendly display name shown in the UI.</summary>
    public string? DisplayName { get; set; }

    /// <summary>Primary organization this user belongs to (optional). See OrganizationMembership
    /// for the full set of memberships that authorize trust domains.</summary>
    public int? OrganizationId { get; set; }

    /// <summary>Identity-proofing state. Authentication (passkey) proves key possession, not that
    /// the requester is a real, vetted person/org — this gate is separate. Placeholder for now;
    /// third-party proofing integration is a later sub-phase.</summary>
    public ProofingStatus ProofingStatus { get; set; } = ProofingStatus.Unverified;
}

/// <summary>Identity-proofing assurance state for a portal user.</summary>
public enum ProofingStatus
{
    /// <summary>No proofing performed.</summary>
    Unverified = 0,

    /// <summary>Proofing submitted and awaiting review.</summary>
    Pending = 1,

    /// <summary>Proofing completed and accepted (eligible for EAB minting later).</summary>
    Verified = 2,

    /// <summary>Proofing was rejected.</summary>
    Rejected = 3,
}
