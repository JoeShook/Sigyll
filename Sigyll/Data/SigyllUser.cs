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

namespace Sigyll.Data;

/// <summary>
/// A CA operator account. This store is deliberately separate from the RA portal's user store
/// (Sigyll.Portal) — portal users are certificate requesters (the public); these are the people
/// who run the CA. Accounts are created by an Admin; there is no self-registration.
/// </summary>
public class SigyllUser : IdentityUser
{
    [PersonalData]
    public string? DisplayName { get; set; }
}

/// <summary>
/// Trusted roles for CA operations, aligned with RFC 3647 §5.2 / NISTIR 7924 role separation.
/// Admin configures the system and manages accounts; CaOperator issues/renews/revokes and
/// manages CRLs; Auditor is read-only. Dual-control ceremonies (Phase 13) layer on top of
/// these — they are workflow gates, not additional roles.
/// </summary>
public static class SigyllRoles
{
    public const string Admin = "Admin";
    public const string CaOperator = "CaOperator";
    public const string Auditor = "Auditor";

    public static readonly string[] All = [Admin, CaOperator, Auditor];
}
