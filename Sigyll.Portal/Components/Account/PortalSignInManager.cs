#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Sigyll.Portal.Data;
using Sigyll.Portal.Services;
using Sigyll.ServiceDefaults;

namespace Sigyll.Portal.Components.Account;

/// <summary>
/// Portal sign-in, with every attempt, lockout and sign-out in the portal's audit trail
/// (<see cref="AuditedSignInManager{TUser}"/>), under the user.* actions.
/// </summary>
public sealed class PortalSignInManager(
    UserManager<PortalUser> userManager,
    IHttpContextAccessor contextAccessor,
    IUserClaimsPrincipalFactory<PortalUser> claimsFactory,
    IOptions<IdentityOptions> optionsAccessor,
    ILogger<SignInManager<PortalUser>> logger,
    IAuthenticationSchemeProvider schemes,
    IUserConfirmation<PortalUser> confirmation,
    PortalAuditTrail audit)
    : AuditedSignInManager<PortalUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
{
    protected override Task RecordAsync(SignInEvent signInEvent, string? account, string detail, bool succeeded) =>
        audit.RecordAsync(account ?? "(unknown account)", signInEvent switch
        {
            SignInEvent.SignedIn => PortalAuditActions.SignedIn,
            SignInEvent.SignInFailed => PortalAuditActions.SignInFailed,
            SignInEvent.LockedOut => PortalAuditActions.LockedOut,
            SignInEvent.SignedOut => PortalAuditActions.SignedOut,
            _ => throw new ArgumentOutOfRangeException(nameof(signInEvent)),
        }, account, detail, succeeded);
}
