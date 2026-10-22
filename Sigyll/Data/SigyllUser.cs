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
