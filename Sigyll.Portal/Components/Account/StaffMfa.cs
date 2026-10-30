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
using Microsoft.AspNetCore.StaticAssets;
using Sigyll.Portal.Data;

namespace Sigyll.Portal.Components.Account;

/// <summary>
/// Portal staff (the RA and PortalAdmin roles) approve certificate requests, so each needs a second factor: an
/// authenticator app or a passkey. Until they have one, staff reach only their account pages, where they set it up;
/// they can't remove their last one; and a staff member whose only second factor is a passkey must finish signing in
/// with it. Requesters may add a second factor but don't have to. Required outside Development; in Development
/// <c>Auth:RequireStaffMfa</c> can turn it off.
/// </summary>
public static class StaffMfa
{
    public const string EnrollPath = "/Account/Manage/TwoFactorAuthentication";

    public static readonly string[] StaffRoles = ["RA", "PortalAdmin"];

    public static bool IsRequired(IConfiguration configuration, IHostEnvironment environment) =>
        !environment.IsDevelopment() || configuration.GetValue("Auth:RequireStaffMfa", true);

    public static async Task<bool> IsStaffAsync(UserManager<PortalUser> users, PortalUser user)
    {
        var roles = await users.GetRolesAsync(user);
        return roles.Any(role => StaffRoles.Contains(role));
    }

    public static async Task<bool> HasSecondFactorAsync(UserManager<PortalUser> users, PortalUser user) =>
        await users.GetTwoFactorEnabledAsync(user) || (await users.GetPasskeysAsync(user)).Count > 0;

    /// <summary>Whether this account may turn off the authenticator app: anyone but staff, or staff with a passkey.</summary>
    public static async Task<bool> CanTurnOffAuthenticatorAsync(UserManager<PortalUser> users, PortalUser user) =>
        !await IsStaffAsync(users, user) || (await users.GetPasskeysAsync(user)).Count > 0;

    /// <summary>Whether this account may remove one passkey: anyone but staff, or staff keeping another factor.</summary>
    public static async Task<bool> CanRemovePasskeyAsync(UserManager<PortalUser> users, PortalUser user) =>
        !await IsStaffAsync(users, user)
        || await users.GetTwoFactorEnabledAsync(user)
        || (await users.GetPasskeysAsync(user)).Count > 1;

    /// <summary>
    /// Whether the password step must stop short of signing in: a staff member whose second factor is a passkey (no
    /// authenticator app, so Identity would ask for nothing more) finishes with the passkey.
    /// </summary>
    public static async Task<bool> NeedsPasskeyAfterPasswordAsync(UserManager<PortalUser> users, PortalUser user) =>
        !await users.GetTwoFactorEnabledAsync(user)
        && (await users.GetPasskeysAsync(user)).Count > 0
        && await IsStaffAsync(users, user);

    /// <summary>
    /// Turns off the authenticator app and revokes the account's recovery codes, which belong to it. Setting the app
    /// up again issues new codes only when none are left, so codes kept here would sign in again.
    /// </summary>
    public static async Task TurnOffAuthenticatorAsync(UserManager<PortalUser> users, PortalUser user)
    {
        var result = await users.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
            throw new InvalidOperationException("Unexpected error occurred disabling 2FA.");
        if (await users.CountRecoveryCodesAsync(user) > 0)
            await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);
    }

    /// <summary>Sends signed-in staff without a second factor to set one up.</summary>
    public static WebApplication UseStaffMfaEnrollment(this WebApplication app)
    {
        if (!IsRequired(app.Configuration, app.Environment))
        {
            app.Logger.LogWarning("Auth:RequireStaffMfa is false: RA staff can sign in without a second factor (Development only)");
            return app;
        }

        app.Use(async (context, next) =>
        {
            if (context.User.Identity?.IsAuthenticated == true
                && StaffRoles.Any(context.User.IsInRole)
                && !IsExempt(context))
            {
                var users = context.RequestServices.GetRequiredService<UserManager<PortalUser>>();
                if (await users.GetUserAsync(context.User) is { } user && !await HasSecondFactorAsync(users, user))
                {
                    context.Response.Redirect($"{EnrollPath}?required=1");
                    return;
                }
            }
            await next();
        });
        return app;
    }

    // Account pages (where the factor is set up, plus sign-out), static assets, health checks, the CSP report
    // endpoint and the error pages stay reachable. Static assets are recognized by their endpoint, since the page
    // links them under content-hashed names (app.{hash}.css).
    private static bool IsExempt(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<StaticAssetDescriptor>() is not null
        || IsExempt(context.Request.Path);

    private static bool IsExempt(PathString path) =>
        path.StartsWithSegments("/Account")
        || path.StartsWithSegments("/_framework")
        || path.StartsWithSegments("/_content")
        || path.StartsWithSegments("/js")
        || path.StartsWithSegments("/lib")
        || path.StartsWithSegments("/Components")
        || path.StartsWithSegments("/health")
        || path.StartsWithSegments("/alive")
        || path.StartsWithSegments(Sigyll.ServiceDefaults.SecurityHeaders.CspReportPath)
        || path.StartsWithSegments("/Error")
        || path.StartsWithSegments("/not-found")
        || path.Value is "/app.css" or "/favicon.png" or "/Sigyll.Portal.styles.css";
}
