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

namespace Sigyll.Components.Account;

/// <summary>
/// Identity's sign-in, with every attempt in the audit trail: who signed in and with which factors, who was refused
/// and why, lockouts, and sign-outs. Every sign-in page goes through here, so none can skip the record. A correct
/// password alone is not recorded: the sign-in it starts is, once the second factor completes it.
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
    : SignInManager<SigyllUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
{
    private PasskeyAssertionResult<SigyllUser>? _assertion;

    public override async Task<SignInResult> PasswordSignInAsync(
        string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        if (await UserManager.FindByNameAsync(userName) is not { } user)
        {
            await RecordAsync(null, AuditActions.OperatorSignInFailed, "Unknown account", succeeded: false, attempted: userName);
            return SignInResult.Failed;
        }
        return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
    }

    public override async Task<SignInResult> PasswordSignInAsync(
        SigyllUser user, string password, bool isPersistent, bool lockoutOnFailure)
    {
        // Failures are recorded by CheckPasswordSignInAsync, which the base calls.
        var result = await base.PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        if (result.Succeeded)
            await RecordAsync(user, AuditActions.OperatorSignedIn, "Password only (no second factor)");
        return result;
    }

    public override async Task<SignInResult> CheckPasswordSignInAsync(SigyllUser user, string password, bool lockoutOnFailure)
    {
        var wasLockedOut = await UserManager.IsLockedOutAsync(user);
        var result = await base.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
        if (!result.Succeeded)
            await RecordFailureAsync(user, result, wasLockedOut, "Wrong password");
        return result;
    }

    public override async Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        var user = await GetTwoFactorAuthenticationUserAsync();
        var wasLockedOut = user is not null && await UserManager.IsLockedOutAsync(user);
        var result = await base.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient);
        if (result.Succeeded)
            await RecordAsync(user, AuditActions.OperatorSignedIn, "Password and authenticator app");
        else
            await RecordFailureAsync(user, result, wasLockedOut, "Wrong authenticator code");
        return result;
    }

    public override async Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)
    {
        var user = await GetTwoFactorAuthenticationUserAsync();
        var wasLockedOut = user is not null && await UserManager.IsLockedOutAsync(user);
        var result = await base.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
        if (result.Succeeded)
        {
            var left = await UserManager.CountRecoveryCodesAsync(user!);
            await RecordAsync(user, AuditActions.OperatorSignedIn, $"Password and recovery code ({left} left)");
        }
        else
        {
            await RecordFailureAsync(user, result, wasLockedOut, "Wrong recovery code");
        }
        return result;
    }

    public override async Task<PasskeyAssertionResult<SigyllUser>> PerformPasskeyAssertionAsync(string credentialJson) =>
        _assertion = await base.PerformPasskeyAssertionAsync(credentialJson);

    public override async Task<SignInResult> PasskeySignInAsync(string credentialJson)
    {
        _assertion = null;
        SignInResult result;
        try
        {
            result = await base.PasskeySignInAsync(credentialJson);
        }
        catch (InvalidOperationException)
        {
            await RecordAsync(null, AuditActions.OperatorSignInFailed, "Passkey prompt expired", succeeded: false);
            throw;
        }

        var user = _assertion?.User;
        if (result.Succeeded)
            await RecordAsync(user, AuditActions.OperatorSignedIn, "Passkey");
        else if (_assertion is { Succeeded: false } refused)
            await RecordAsync(null, AuditActions.OperatorSignInFailed, $"Passkey refused: {refused.Failure.Message}", succeeded: false);
        else
            await RecordFailureAsync(user, result, wasLockedOut: result.IsLockedOut, "Passkey refused");
        return result;
    }

    public override async Task SignOutAsync()
    {
        var account = Context.User.Identity is { IsAuthenticated: true } identity ? identity.Name : null;
        await base.SignOutAsync();
        if (account is not null)
            await RecordSessionEndAsync(audit, Context, account, "Signed out");
    }

    /// <summary>Records a session that ended without the operator signing out: idle, or at its time limit.</summary>
    public static Task RecordSessionEndAsync(AuditTrail audit, HttpContext http, string account, string reason) =>
        audit.RecordAsync(Actor(account), AuditActions.OperatorSignedOut, AuditTarget.Operator(account), From(http, reason));

    private async Task RecordFailureAsync(SigyllUser? user, SignInResult result, bool wasLockedOut, string reason)
    {
        if (wasLockedOut)
        {
            await RecordAsync(user, AuditActions.OperatorSignInFailed, "Account locked", succeeded: false);
            return;
        }

        await RecordAsync(user, AuditActions.OperatorSignInFailed, result.IsNotAllowed ? "Sign-in not allowed" : reason,
            succeeded: false);
        if (result.IsLockedOut && user is not null)
        {
            var until = await UserManager.GetLockoutEndDateAsync(user);
            await RecordAsync(user, AuditActions.OperatorLockedOut,
                $"After {Options.Lockout.MaxFailedAccessAttempts} failed attempts; locked until {until:u}");
        }
    }

    private Task RecordAsync(SigyllUser? user, string action, string detail, bool succeeded = true, string? attempted = null)
    {
        var account = user?.Email ?? user?.UserName ?? AttemptedAccount(attempted);
        return audit.RecordAsync(Actor(account ?? "(unknown account)"), action,
            account is null ? null : AuditTarget.Operator(account), From(Context, detail), succeeded);
    }

    private static OperatorIdentity Actor(string account) => new(account, new HashSet<Permission>());

    private static string From(HttpContext http, string detail) =>
        http.Connection.RemoteIpAddress is { } address ? $"{detail}; from {address}" : detail;

    /// <summary>
    /// The account name typed for an unknown account, kept only when it looks like one (an email address): operators
    /// sometimes type their password into the wrong box, and the audit trail must not keep it.
    /// </summary>
    private static string? AttemptedAccount(string? typed) =>
        typed is { Length: > 0 and <= 256 } && typed.Contains('@') && !typed.Any(char.IsWhiteSpace) ? typed : null;
}
