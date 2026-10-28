#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Sigyll.ServiceDefaults;

namespace Sigyll.Signing.Tests;

public class SecurityHeadersTests
{
    [Fact]
    public async Task EveryResponse_CarriesTheHeaders_WithTheContentSecurityPolicyReportOnlyByDefault()
    {
        await using var app = await StartAsync(enforce: null);
        using var client = Client(app);

        using var response = await client.GetAsync("/");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        Header(response, "X-Content-Type-Options").ShouldBe("nosniff");
        Header(response, "X-Frame-Options").ShouldBe("DENY");
        Header(response, "Referrer-Policy").ShouldBe("same-origin");
        Header(response, "Cross-Origin-Opener-Policy").ShouldBe("same-origin");
        Header(response, "Permissions-Policy").ShouldContain("camera=()");
        response.Headers.Contains("Content-Security-Policy").ShouldBeFalse();
        var csp = Header(response, "Content-Security-Policy-Report-Only");
        csp.ShouldContain("script-src 'self';");
        csp.ShouldContain("frame-ancestors 'none'");
        csp.ShouldContain("report-uri " + SecurityHeaders.CspReportPath);
    }

    [Fact]
    public async Task ContentSecurityPolicy_IsEnforced_WhenConfigured()
    {
        await using var app = await StartAsync(enforce: true);
        using var client = Client(app);

        using var response = await client.GetAsync("/");

        Header(response, "Content-Security-Policy").ShouldContain("script-src 'self';");
        response.Headers.Contains("Content-Security-Policy-Report-Only").ShouldBeFalse();
    }

    [Fact]
    public async Task CspReports_AreAcceptedAnonymously_AndAnythingElseIsRefused()
    {
        await using var app = await StartAsync(enforce: null);
        using var client = Client(app);
        const string report = """{"csp-report":{"violated-directive":"script-src","blocked-uri":"inline"}}""";

        using var accepted = await client.PostAsync(SecurityHeaders.CspReportPath,
            new StringContent(report, Encoding.UTF8, "application/csp-report"));
        accepted.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        using var refused = await client.PostAsync(SecurityHeaders.CspReportPath,
            new StringContent("hello", Encoding.UTF8, "text/plain"));
        refused.StatusCode.ShouldBe(HttpStatusCode.UnsupportedMediaType);
    }

    private static async Task<WebApplication> StartAsync(bool? enforce)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        if (enforce is { } value)
            builder.Configuration["SecurityHeaders:EnforceContentSecurityPolicy"] = value.ToString();
        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery();

        var app = builder.Build();
        app.UseSecurityHeaders();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapGet("/", () => "ok");
        await app.StartAsync();
        return app;
    }

    private static HttpClient Client(WebApplication app) => new()
    {
        BaseAddress = new Uri(app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.First())
    };

    private static string Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? string.Join(", ", values) : "";
}
