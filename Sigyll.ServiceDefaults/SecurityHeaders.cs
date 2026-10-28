#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Sigyll.ServiceDefaults;

/// <summary>
/// Browser-facing response headers for the Blazor apps: no framing, no MIME sniffing, no referrer
/// leaking off-site, no camera/microphone/location, and a content security policy that only runs
/// the app's own scripts.
/// </summary>
/// <remarks>
/// The content security policy is report-only until <c>SecurityHeaders:EnforceContentSecurityPolicy</c>
/// is true. Either way, violations are posted to <see cref="CspReportPath"/> and logged as warnings.
/// </remarks>
public static class SecurityHeaders
{
    public const string CspReportPath = "/csp-report";

    // Blazor and Fluent UI need inline styles (style attributes and the reconnect dialog), not inline scripts.
    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: blob:; " +
        "font-src 'self' data:; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'; " +
        "report-uri " + CspReportPath;

    private const int MaxReportBytes = 16 * 1024;

    public static WebApplication UseSecurityHeaders(this WebApplication app)
    {
        var enforce = app.Configuration.GetValue("SecurityHeaders:EnforceContentSecurityPolicy", false);
        var cspHeader = enforce ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only";

        app.Use(async (context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.XContentTypeOptions = "nosniff";
                headers.XFrameOptions = "DENY";
                headers["Referrer-Policy"] = "same-origin";
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
                headers["Cross-Origin-Opener-Policy"] = "same-origin";
                headers[cspHeader] = ContentSecurityPolicy;
                return Task.CompletedTask;
            });
            await next();
        });

        // Browsers post reports anonymously; anything that isn't a CSP report is refused, and a report is
        // logged no longer than MaxReportBytes.
        app.MapPost(CspReportPath, async (HttpRequest request, ILoggerFactory loggers) =>
        {
            var contentType = request.ContentType ?? "";
            if (!contentType.StartsWith("application/csp-report", StringComparison.OrdinalIgnoreCase)
                && !contentType.StartsWith("application/reports+json", StringComparison.OrdinalIgnoreCase))
                return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);

            using var reader = new StreamReader(request.Body);
            var buffer = new char[MaxReportBytes];
            var length = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
            loggers.CreateLogger("Sigyll.ContentSecurityPolicy")
                .LogWarning("Content security policy violation: {Report}", new string(buffer, 0, length));
            return Results.NoContent();
        }).AllowAnonymous().DisableAntiforgery();

        return app;
    }
}
