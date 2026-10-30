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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sigyll.ServiceDefaults;

/// <summary>The sign-in events an app's audit trail records.</summary>
public enum SignInEvent
{
    SignedIn,
    SignInFailed,
    LockedOut,
    SignedOut,
}

/// <summary>
/// Identity's sign-in with every attempt audited: who signed in and with which factors, who was refused and why,
/// lockouts, and sign-outs. Each app (Sigyll, the Portal) says where the events go. Every sign-in page goes through
/// the sign-in manager, so none can skip the record. A correct password alone is not recorded when a second factor
/// follows: the sign-in it starts is, once the second factor completes it.
/// </summary>
public abstract class AuditedSignInManager<TUser>(
    UserManager<TUser> userManager,
    IHttpContextAccessor contextAccessor,
    IUserClaimsPrincipalFactory<TUser> claimsFactory,
    IOptions<IdentityOptions> optionsAccessor,
    ILogger<SignInManager<TUser>> logger,
    IAuthenticationSchemeProvider schemes,
    IUserConfirmation<TUser> confirmation)
    : SignInManager<TUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    where TUser : class
{
    private PasskeyAssertionResult<TUser>? _assertion;

    /// <summary>
    /// Stores one event. <paramref name="account"/> is the account's email (or user name); null when the attempt
    /// names no known account. <paramref name="detail"/> already ends with the client's address.
    /// </summary>
    protected abstract Task RecordAsync(SignInEvent signInEvent, string? account, string detail, bool succeeded);

    public override async Task<SignInResult> PasswordSignInAsync(
        string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        if (await UserManager.FindByNameAsync(userName) is not { } user)
        {
            await RecordAsync(SignInEvent.SignInFailed, AttemptedAccount(userName), From("Unknown account"), succeeded: false);
            return SignInResult.Failed;
        }
        return await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
    }

    public override async Task<SignInResult> PasswordSignInAsync(
        TUser user, string password, bool isPersistent, bool lockoutOnFailure)
    {
        // Failures are recorded by CheckPasswordSignInAsync, which the base calls.
        var result = await base.PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        if (result.Succeeded)
            await RecordAsync(user, SignInEvent.SignedIn, "Password only");
        return result;
    }

    public override async Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure)
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
            await RecordAsync(user, SignInEvent.SignedIn, "Password and authenticator app");
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
            await RecordAsync(user, SignInEvent.SignedIn, $"Password and recovery code ({left} left)");
        }
        else
        {
            await RecordFailureAsync(user, result, wasLockedOut, "Wrong recovery code");
        }
        return result;
    }

    public override async Task<PasskeyAssertionResult<TUser>> PerformPasskeyAssertionAsync(string credentialJson) =>
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
            await RecordAsync(SignInEvent.SignInFailed, null, From("Passkey prompt expired"), succeeded: false);
            throw;
        }

        var user = _assertion?.User;
        if (result.Succeeded)
            await RecordAsync(user, SignInEvent.SignedIn, "Passkey");
        else if (_assertion is { Succeeded: false } refused)
            await RecordAsync(SignInEvent.SignInFailed, null, From($"Passkey refused: {refused.Failure.Message}"), succeeded: false);
        else
            await RecordFailureAsync(user, result, wasLockedOut: result.IsLockedOut, "Passkey refused");
        return result;
    }

    public override async Task SignOutAsync()
    {
        var account = Context.User.Identity is { IsAuthenticated: true } identity ? identity.Name : null;
        await base.SignOutAsync();
        if (account is not null)
            await RecordAsync(SignInEvent.SignedOut, account, From("Signed out"), succeeded: true);
    }

    /// <summary><paramref name="detail"/>, followed by the address the request came from, when known.</summary>
    protected string From(string detail) => From(Context, detail);

    public static string From(HttpContext http, string detail) =>
        http.Connection.RemoteIpAddress is { } address ? $"{detail}; from {address}" : detail;

    private async Task RecordFailureAsync(TUser? user, SignInResult result, bool wasLockedOut, string reason)
    {
        if (wasLockedOut)
        {
            await RecordAsync(user, SignInEvent.SignInFailed, "Account locked", succeeded: false);
            return;
        }

        await RecordAsync(user, SignInEvent.SignInFailed, result.IsNotAllowed ? "Sign-in not allowed" : reason, succeeded: false);
        if (result.IsLockedOut && user is not null)
        {
            var until = await UserManager.GetLockoutEndDateAsync(user);
            await RecordAsync(user, SignInEvent.LockedOut,
                $"After {Options.Lockout.MaxFailedAccessAttempts} failed attempts; locked until {until:u}");
        }
    }

    private async Task RecordAsync(TUser? user, SignInEvent signInEvent, string detail, bool succeeded = true)
    {
        var account = user is null ? null : await UserManager.GetEmailAsync(user) ?? await UserManager.GetUserNameAsync(user);
        await RecordAsync(signInEvent, account, From(detail), succeeded);
    }

    /// <summary>
    /// The account name typed for an unknown account, kept only when it looks like one (an email address): people
    /// sometimes type their password into the wrong box, and the audit trail must not keep it.
    /// </summary>
    private static string? AttemptedAccount(string? typed) =>
        typed is { Length: > 0 and <= 256 } && typed.Contains('@') && !typed.Any(char.IsWhiteSpace) ? typed : null;
}
