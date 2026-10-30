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
using Sigyll.Common.Security;
using Sigyll.Common.Services.Audit;
using Sigyll.Data;
using Sigyll.ServiceDefaults;

namespace Sigyll.Components.Account;

/// <summary>
/// Operator sign-in, with every attempt, lockout and sign-out in the CA's audit trail
/// (<see cref="AuditedSignInManager{TUser}"/>), under the operator.* actions.
/// </summary>
public sealed class OperatorSignInManager(
    UserManager<SigyllUser> userManager,
    IHttpContextAccessor contextAccessor,
    IUserClaimsPrincipalFactory<SigyllUser> claimsFactory,
    IOptions<IdentityOptions> optionsAccessor,
    ILogger<SignInManager<SigyllUser>> logger,
    IAuthenticationSchemeProvider schemes,
    IUserConfirmation<SigyllUser> confirmation,
    AuditTrail audit)
    : AuditedSignInManager<SigyllUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
{
    protected override Task RecordAsync(SignInEvent signInEvent, string? account, string detail, bool succeeded) =>
        audit.RecordAsync(Actor(account ?? "(unknown account)"), Action(signInEvent),
            account is null ? null : AuditTarget.Operator(account), detail, succeeded);

    /// <summary>Records a session that ended without the operator signing out: idle, or at its time limit.</summary>
    public static Task RecordSessionEndAsync(AuditTrail audit, HttpContext http, string account, string reason) =>
        audit.RecordAsync(Actor(account), AuditActions.OperatorSignedOut, AuditTarget.Operator(account), From(http, reason));

    private static string Action(SignInEvent signInEvent) => signInEvent switch
    {
        SignInEvent.SignedIn => AuditActions.OperatorSignedIn,
        SignInEvent.SignInFailed => AuditActions.OperatorSignInFailed,
        SignInEvent.LockedOut => AuditActions.OperatorLockedOut,
        SignInEvent.SignedOut => AuditActions.OperatorSignedOut,
        _ => throw new ArgumentOutOfRangeException(nameof(signInEvent)),
    };

    private static OperatorIdentity Actor(string account) => new(account, new HashSet<Permission>());
}
