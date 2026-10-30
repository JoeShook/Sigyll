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
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sigyll.Components.Account;
using Sigyll.Data;

namespace Sigyll.Auth.Tests;

/// <summary>
/// The enrollment gate (OperatorMfa.UseOperatorMfaEnrollment): a signed-in operator without a second factor reaches
/// only the pages where they set one up.
/// </summary>
public class MfaEnrollmentTests
{
    private const string UserHeader = "X-Test-User";

    [Theory]
    [InlineData("/")]
    [InlineData("/certificates")]
    [InlineData("/admin/operators")]
    [InlineData("/Accounts")]
    [InlineData("/healthz")]
    [InlineData("/favicon.png.html")]
    public async Task WithoutAFactor_PagesRedirectToSetup(string path)
    {
        await using var site = await TestSite.StartAsync();
        var userId = await site.CreateOperatorAsync();

        var response = await site.GetAsync(path, userId);

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.ShouldBe($"{OperatorMfa.EnrollPath}?required=1");
    }

    [Fact]
    public async Task WithoutAFactor_ApiCallsAreRefused()
    {
        await using var site = await TestSite.StartAsync();
        var userId = await site.CreateOperatorAsync();

        (await site.GetAsync("/api/certificates/1/download", userId)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Theory]
    [InlineData("/Account/Manage/TwoFactorAuthentication")]
    [InlineData("/Account/Manage/EnableAuthenticator")]
    [InlineData("/Account/Manage/Passkeys")]
    [InlineData("/Account/Logout")]
    [InlineData("/Account/KeepAlive")]
    [InlineData("/_framework/blazor.web.js")]
    [InlineData("/_content/Microsoft.FluentUI.AspNetCore.Components/css/reboot.css")]
    [InlineData("/css/app.css")]
    [InlineData("/js/sigyll.js")]
    [InlineData("/Components/Account/Shared/PasskeySubmit.razor.js")]
    [InlineData("/health")]
    [InlineData("/alive")]
    [InlineData("/csp-report")]
    [InlineData("/Error")]
    [InlineData("/favicon.png")]
    [InlineData("/Sigyll.styles.css")]
    public async Task WithoutAFactor_SetupPagesAndAssetsStayReachable(string path)
    {
        await using var site = await TestSite.StartAsync();
        var userId = await site.CreateOperatorAsync();

        (await site.GetAsync(path, userId)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    [InlineData(true, 2)]
    public async Task WithAFactor_EverythingIsReachable(bool authenticator, int passkeys)
    {
        await using var site = await TestSite.StartAsync();
        var userId = await site.CreateOperatorAsync(authenticator, passkeys);

        (await site.GetAsync("/certificates", userId)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await site.GetAsync("/api/certificates/1/download", userId)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task AnonymousRequests_AreLeftToAuthorization()
    {
        await using var site = await TestSite.StartAsync();

        (await site.GetAsync("/certificates", userId: null)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task InDevelopment_TheGateCanBeTurnedOff()
    {
        await using var site = await TestSite.StartAsync("Development", requireMfa: "false");
        var userId = await site.CreateOperatorAsync();

        (await site.GetAsync("/certificates", userId)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task OutsideDevelopment_TheGateCanNotBeTurnedOff(string environment)
    {
        await using var site = await TestSite.StartAsync(environment, requireMfa: "false");
        var userId = await site.CreateOperatorAsync();

        (await site.GetAsync("/certificates", userId)).StatusCode.ShouldBe(HttpStatusCode.Redirect);
    }

    [Theory]
    [InlineData("Production", null, true)]
    [InlineData("Production", "false", true)]
    [InlineData("Development", null, true)]
    [InlineData("Development", "true", true)]
    [InlineData("Development", "false", false)]
    public void IsRequired_OnlyDevelopmentCanTurnItOff(string environment, string? requireMfa, bool required)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Auth:RequireMfa"] = requireMfa })
            .Build();
        var host = new TestIdentity.TestHostEnvironment(environment);

        OperatorMfa.IsRequired(configuration, host).ShouldBe(required);
    }

    /// <summary>The gate between a stand-in for authentication (the user id in a header) and endpoints that answer 200.</summary>
    private sealed class TestSite : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _database;
        private readonly HttpClient _client;

        private TestSite(WebApplication app, SqliteConnection database)
        {
            _app = app;
            _database = database;
            _client = app.GetTestClient();
        }

        public static async Task<TestSite> StartAsync(string environment = "Production", string? requireMfa = null)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
            builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Auth:RequireMfa"] = requireMfa });
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            var database = TestIdentity.OpenDatabase();
            builder.Services.AddDbContext<SigyllAuthDbContext>(options => options.UseSqlite(database));
            TestIdentity.AddAuditTrail(builder.Services, TestIdentity.AuditDb());
            builder.Services.AddOperatorIdentity(builder.Configuration);

            var app = builder.Build();
            TestIdentity.CreateSchema(app.Services);
            app.Use((context, next) =>
            {
                if (context.Request.Headers.TryGetValue(UserHeader, out var id))
                    context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, id.ToString())], "Test"));
                return next(context);
            });
            app.UseOperatorMfaEnrollment();
            app.Map("/{**path}", () => "ok");
            await app.StartAsync();
            return new TestSite(app, database);
        }

        public async Task<string> CreateOperatorAsync(bool authenticator = false, int passkeys = 0)
        {
            using var scope = _app.Services.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<SigyllUser>>();
            var email = $"{Guid.NewGuid():N}@sigyll.test";
            var user = new SigyllUser { UserName = email, Email = email, EmailConfirmed = true };
            (await users.CreateAsync(user, TestIdentity.Password)).Succeeded.ShouldBeTrue();
            if (authenticator)
                (await users.SetTwoFactorEnabledAsync(user, true)).Succeeded.ShouldBeTrue();
            for (var i = 0; i < passkeys; i++)
                (await users.AddOrUpdatePasskeyAsync(user, TestIdentity.Passkey())).Succeeded.ShouldBeTrue();
            return user.Id;
        }

        public Task<HttpResponseMessage> GetAsync(string path, string? userId)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, path);
            if (userId != null) request.Headers.Add(UserHeader, userId);
            return _client.SendAsync(request);
        }

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _app.DisposeAsync();
            await _database.DisposeAsync();
        }
    }
}
