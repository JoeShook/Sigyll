#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.Identity;

namespace Sigyll.Components.Account;

/// <summary>
/// How long an operator stays signed in, and when failed sign-ins lock an account. Configuration section
/// <c>Auth:Session</c>.
/// </summary>
public sealed class OperatorSessionOptions
{
    public const string SectionName = "Auth:Session";

    /// <summary>Signed out after this long without activity.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Signed out this long after signing in, however active.</summary>
    public TimeSpan MaxSessionLength { get; set; } = TimeSpan.FromHours(8);

    /// <summary>Failed passwords or codes in a row that lock the account.</summary>
    public int LockoutAttempts { get; set; } = 5;

    /// <summary>How long a locked account stays locked.</summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
}

/// <summary>
/// Operator session limits. The sign-in cookie expires after the idle timeout and slides only on real requests; the
/// browser pings <see cref="KeepAlivePath"/> while the operator is active (an interactive page makes no requests of its
/// own) and leaves through <see cref="ExpiredPath"/> when idle. The session start is stamped at sign-in and carried
/// through cookie renewal, so the absolute limit holds however active the operator is. Open circuits are checked by
/// <see cref="IdentityRevalidatingAuthenticationStateProvider"/>, so a page left open without the script still ends.
/// </summary>
public static class OperatorSession
{
    public const string StartClaimType = "sigyll:session_start";
    public const string KeepAlivePath = "/Account/KeepAlive";
    public const string ExpiredPath = "/Account/SessionExpired";
    private const string StartItem = ".sigyll.session_start";

    public static IServiceCollection AddOperatorSession(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection(OperatorSessionOptions.SectionName).Get<OperatorSessionOptions>()
                      ?? new OperatorSessionOptions();
        services.AddSingleton(options);
        services.AddScoped<CircuitActivity>();
        services.AddScoped<CircuitHandler, CircuitActivityHandler>();

        services.Configure<IdentityOptions>(identity =>
        {
            identity.Lockout.AllowedForNewUsers = true;
            identity.Lockout.MaxFailedAccessAttempts = options.LockoutAttempts;
            identity.Lockout.DefaultLockoutTimeSpan = options.LockoutDuration;
        });

        services.ConfigureApplicationCookie(cookie =>
        {
            cookie.ExpireTimeSpan = options.IdleTimeout;
            cookie.SlidingExpiration = true;
            cookie.Events.OnSigningIn = context =>
            {
                // Keep the original start through renewals and refreshed sign-ins; stamp it on the first.
                var items = context.Properties.Items;
                if (!items.TryGetValue(StartItem, out var start) || start is null)
                    items[StartItem] = start = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                if (context.Principal?.Identity is ClaimsIdentity identity && !identity.HasClaim(c => c.Type == StartClaimType))
                    identity.AddClaim(new Claim(StartClaimType, start));
                context.Properties.IsPersistent = false;
                return Task.CompletedTask;
            };
            var validateStamp = cookie.Events.OnValidatePrincipal;
            cookie.Events.OnValidatePrincipal = async context =>
            {
                if (IsPastMaxLength(context.Principal, options))
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
                    return;
                }
                await validateStamp(context);
            };
        });
        return services;
    }

    /// <summary>Whether the session that issued this principal began longer ago than the maximum.</summary>
    public static bool IsPastMaxLength(ClaimsPrincipal? principal, OperatorSessionOptions options)
    {
        var value = principal?.FindFirst(StartClaimType)?.Value;
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            return principal?.Identity?.IsAuthenticated == true;   // a session without a start predates this check
        return DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(seconds) > options.MaxSessionLength;
    }

    /// <summary>The keep-alive and expiry endpoints the browser's idle tracker uses.</summary>
    public static void MapOperatorSessionEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // An authenticated request: the cookie handler slides the expiry, and refuses a session past its maximum.
        endpoints.MapPost(KeepAlivePath, () => Results.NoContent()).RequireAuthorization();

        endpoints.MapGet(ExpiredPath, async (HttpContext http) =>
        {
            await http.SignOutAsync(IdentityConstants.ApplicationScheme);
            return Results.LocalRedirect("~/Account/Login?expired=1");
        });
    }
}

/// <summary>When the operator last did something in this circuit.</summary>
public sealed class CircuitActivity
{
    public DateTimeOffset LastActivity { get; private set; } = DateTimeOffset.UtcNow;
    public void Touch() => LastActivity = DateTimeOffset.UtcNow;
}

/// <summary>Records every inbound circuit event (clicks, input, navigation) as activity.</summary>
internal sealed class CircuitActivityHandler(CircuitActivity activity) : CircuitHandler
{
    public override Func<CircuitInboundActivityContext, Task> CreateInboundActivityHandler(
        Func<CircuitInboundActivityContext, Task> next) => context =>
    {
        activity.Touch();
        return next(context);
    };
}
