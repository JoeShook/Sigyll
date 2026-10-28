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
using Sigyll.Data;

namespace Sigyll.Components.Account;

/// <summary>
/// Every operator needs a second factor: an authenticator app (time-based codes, RFC 6238, which any authenticator
/// app produces) or a passkey. Until they have one, an operator can reach only their account pages, where they set
/// it up; and they can't remove their last one. Required outside Development; in Development <c>Auth:RequireMfa</c>
/// can turn it off.
/// </summary>
public static class OperatorMfa
{
    public const string EnrollPath = "/Account/Manage/TwoFactorAuthentication";

    public static bool IsRequired(IConfiguration configuration, IHostEnvironment environment) =>
        !environment.IsDevelopment() || configuration.GetValue("Auth:RequireMfa", true);

    public static async Task<bool> HasSecondFactorAsync(UserManager<SigyllUser> users, SigyllUser user) =>
        await users.GetTwoFactorEnabledAsync(user) || (await users.GetPasskeysAsync(user)).Count > 0;

    /// <summary>Sends signed-in operators without a second factor to set one up; API calls get 403.</summary>
    public static WebApplication UseOperatorMfaEnrollment(this WebApplication app)
    {
        if (!IsRequired(app.Configuration, app.Environment))
        {
            Serilog.Log.Warning("Auth:RequireMfa is false: operators can sign in without a second factor (Development only)");
            return app;
        }

        app.Use(async (context, next) =>
        {
            if (context.User.Identity?.IsAuthenticated == true && !IsExempt(context.Request.Path))
            {
                var users = context.RequestServices.GetRequiredService<UserManager<SigyllUser>>();
                if (await users.GetUserAsync(context.User) is { } user && !await HasSecondFactorAsync(users, user))
                {
                    if (context.Request.Path.StartsWithSegments("/api"))
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    else
                        context.Response.Redirect($"{EnrollPath}?required=1");
                    return;
                }
            }
            await next();
        });
        return app;
    }

    // Account pages (where the factor is set up, plus sign-out and session endpoints), static assets, health checks
    // and the CSP report endpoint stay reachable.
    private static bool IsExempt(PathString path) =>
        path.StartsWithSegments("/Account")
        || path.StartsWithSegments("/_framework")
        || path.StartsWithSegments("/_content")
        || path.StartsWithSegments("/css")
        || path.StartsWithSegments("/js")
        || path.StartsWithSegments("/Components")
        || path.StartsWithSegments("/health")
        || path.StartsWithSegments("/alive")
        || path.StartsWithSegments(Sigyll.ServiceDefaults.SecurityHeaders.CspReportPath)
        || path.StartsWithSegments("/Error")
        || path.Value is "/favicon.png" or "/Sigyll.styles.css";
}
