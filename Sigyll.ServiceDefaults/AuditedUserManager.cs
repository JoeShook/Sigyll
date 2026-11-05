#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Sigyll.ServiceDefaults;

/// <summary>
/// Identity's account manager, with every change people make to their own sign-in security audited: the
/// authenticator app turned on or off or its key reset, recovery codes issued or revoked, passkeys added, renamed
/// or removed, and passwords changed, set, removed or reset by an emailed link. Each app says where the events go.
/// Every account page changes accounts through here, so none can skip the record.
/// </summary>
/// <remarks>
/// Only changes made by the signed-in account to itself are recorded here (and a password reset by link, made
/// signed out). An administrator changing someone else's account is recorded by the page that does it, with the
/// administrator as the actor; Identity's own bookkeeping during sign-in (a passkey's signature counter) is not a
/// change anyone made.
/// </remarks>
public abstract class AuditedUserManager<TUser>(
    IUserStore<TUser> store,
    IOptions<IdentityOptions> optionsAccessor,
    IPasswordHasher<TUser> passwordHasher,
    IEnumerable<IUserValidator<TUser>> userValidators,
    IEnumerable<IPasswordValidator<TUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<TUser>> logger,
    IHttpContextAccessor httpContextAccessor)
    : UserManager<TUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer,
        errors, services, logger)
    where TUser : class
{
    /// <summary>Stores one event about <paramref name="account"/> (its email, or user name), made by itself.</summary>
    protected abstract Task RecordAsync(string account, string detail);

    public override async Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled)
    {
        var record = await ChangedBySelfAsync(user) && await GetTwoFactorEnabledAsync(user) != enabled;
        var result = await base.SetTwoFactorEnabledAsync(user, enabled);
        if (record && result.Succeeded)
            await RecordAsync(user, enabled ? "Authenticator app turned on" : "Authenticator app turned off");
        return result;
    }

    public override async Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user)
    {
        var record = await ChangedBySelfAsync(user);
        var result = await base.ResetAuthenticatorKeyAsync(user);
        if (record && result.Succeeded)
            await RecordAsync(user, "Authenticator app key reset");
        return result;
    }

    public override async Task<IEnumerable<string>?> GenerateNewTwoFactorRecoveryCodesAsync(TUser user, int number)
    {
        var record = await ChangedBySelfAsync(user);
        var before = record ? await CountRecoveryCodesAsync(user) : 0;
        var codes = await base.GenerateNewTwoFactorRecoveryCodesAsync(user, number);
        if (record && codes is not null)
        {
            if (number > 0)
                await RecordAsync(user, before > 0
                    ? $"New recovery codes issued ({number}); the {before} unused ones revoked"
                    : $"New recovery codes issued ({number})");
            else if (before > 0)
                await RecordAsync(user, $"Recovery codes revoked ({before})");
        }
        return codes;
    }

    public override async Task<IdentityResult> AddOrUpdatePasskeyAsync(TUser user, UserPasskeyInfo passkey)
    {
        var record = await ChangedBySelfAsync(user);
        var existing = record ? await GetPasskeyAsync(user, passkey.CredentialId) : null;
        var result = await base.AddOrUpdatePasskeyAsync(user, passkey);
        if (record && result.Succeeded)
        {
            if (existing is null)
                await RecordAsync(user, $"Passkey added{Named(passkey.Name)}");
            else if (existing.Name != passkey.Name)
                await RecordAsync(user, string.IsNullOrWhiteSpace(existing.Name)
                    ? $"Passkey named \"{passkey.Name}\""
                    : $"Passkey renamed from \"{existing.Name}\" to \"{passkey.Name}\"");
        }
        return result;
    }

    public override async Task<IdentityResult> RemovePasskeyAsync(TUser user, byte[] credentialId)
    {
        var record = await ChangedBySelfAsync(user);
        var existing = record ? await GetPasskeyAsync(user, credentialId) : null;
        var result = await base.RemovePasskeyAsync(user, credentialId);
        if (record && result.Succeeded && existing is not null)
            await RecordAsync(user, $"Passkey removed{Named(existing.Name)}");
        return result;
    }

    public override async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
    {
        var record = await ChangedBySelfAsync(user);
        var result = await base.ChangePasswordAsync(user, currentPassword, newPassword);
        if (record && result.Succeeded)
            await RecordAsync(user, "Password changed");
        return result;
    }

    public override async Task<IdentityResult> AddPasswordAsync(TUser user, string password)
    {
        var record = await ChangedBySelfAsync(user);
        var result = await base.AddPasswordAsync(user, password);
        if (record && result.Succeeded)
            await RecordAsync(user, "Password set");
        return result;
    }

    public override async Task<IdentityResult> RemovePasswordAsync(TUser user)
    {
        var record = await ChangedBySelfAsync(user);
        var result = await base.RemovePasswordAsync(user);
        if (record && result.Succeeded)
            await RecordAsync(user, "Password removed");
        return result;
    }

    public override async Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)
    {
        // Signed out, this is the forgotten-password link; signed in, an administrator setting a password, which
        // their page records.
        var record = httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated == false;
        var result = await base.ResetPasswordAsync(user, token, newPassword);
        if (record && result.Succeeded)
            await RecordAsync(user, "Password reset with an emailed link");
        return result;
    }

    /// <summary>Whether the request is the signed-in account changing itself.</summary>
    private async Task<bool> ChangedBySelfAsync(TUser user) =>
        httpContextAccessor.HttpContext?.User is { Identity.IsAuthenticated: true } principal
        && principal.FindFirstValue(Options.ClaimsIdentity.UserIdClaimType) == await GetUserIdAsync(user);

    private async Task RecordAsync(TUser user, string detail)
    {
        var account = await GetEmailAsync(user) ?? await GetUserNameAsync(user) ?? await GetUserIdAsync(user);
        var http = httpContextAccessor.HttpContext;
        await RecordAsync(account, http is null ? detail : AuditedSignInManager<TUser>.From(http, detail));
    }

    private static string Named(string? name) => string.IsNullOrWhiteSpace(name) ? "" : $" (\"{name}\")";
}
