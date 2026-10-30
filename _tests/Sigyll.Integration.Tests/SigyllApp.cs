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
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Data;
using Sigyll.Tests;
using Testcontainers.PostgreSql;

namespace Sigyll.Integration.Tests;

[CollectionDefinition(Name)]
public sealed class SigyllAppCollection : ICollectionFixture<SigyllApp>
{
    public const string Name = "Sigyll";
}

/// <summary>
/// Sigyll as it runs in production: its own startup (Program.cs), over PostgreSQL in Docker with the schema the
/// Flyway scripts in dist/AlloyDB build. One app per test run; Serilog's startup logger allows only one host.
/// </summary>
public sealed class SigyllApp : IAsyncLifetime
{
    public const string Password = "Correct-horse-battery-1";

    /// <summary>Sessions end this long after sign-in, however active; short enough to test.</summary>
    public static readonly TimeSpan MaxSessionLength = TimeSpan.FromSeconds(15);

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17.6")
        .WithDatabase("sigil")
        .Build();

    private WebApplicationFactory<Program> _factory = null!;

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        await FlywaySchema.ApplyAsync(_postgres.GetConnectionString(), "sigil");

        // Program reads its configuration while registering services, before a test host could add any, so the
        // settings go in as environment variables, as a deployment's would.
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
        Environment.SetEnvironmentVariable("ConnectionStrings__SigyllDb", _postgres.GetConnectionString());
        Environment.SetEnvironmentVariable("KeyProtection__MasterKey", Convert.ToBase64String(new byte[32]));
        Environment.SetEnvironmentVariable("Auth__BootstrapAdmin__Email", "admin@sigyll.test");
        Environment.SetEnvironmentVariable("Auth__BootstrapAdmin__Password", Password);
        Environment.SetEnvironmentVariable("Auth__Session__MaxSessionLength", MaxSessionLength.ToString());
        _factory = new WebApplicationFactory<Program>();
        _ = _factory.Server;   // start it now, not in the first test's time
    }

    public async Task DisposeAsync()
    {
        await _factory.DisposeAsync();
        await _postgres.DisposeAsync();
    }

    /// <summary>A browser: keeps cookies, follows redirects, speaks HTTPS (the session cookie is Secure).</summary>
    public HttpClient Browser() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = true,
        HandleCookies = true,
    });

    /// <summary>A new operator with a role and, if asked, the authenticator app; returns its authenticator key.</summary>
    public async Task<string?> CreateOperatorAsync(string email, bool authenticator = true)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SigyllUser>>();
        var user = new SigyllUser { UserName = email, Email = email, EmailConfirmed = true };
        (await users.CreateAsync(user, Password)).Succeeded.ShouldBeTrue();
        (await users.AddToRoleAsync(user, SigyllRoles.Auditor)).Succeeded.ShouldBeTrue();
        if (!authenticator)
            return null;
        await users.ResetAuthenticatorKeyAsync(user);
        await users.SetTwoFactorEnabledAsync(user, true);
        return await users.GetAuthenticatorKeyAsync(user);
    }

    public async Task<IReadOnlyList<string>> RecoveryCodesAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<SigyllUser>>();
        return [.. (await users.GenerateNewTwoFactorRecoveryCodesAsync((await users.FindByEmailAsync(email))!, 10))!];
    }

    /// <summary>Runs SQL against the database directly, as someone with database access could.</summary>
    public Task ExecuteSqlAsync(string sql) => FlywaySchema.ExecuteAsync(_postgres.GetConnectionString(), sql);

    /// <summary>The audit trail's events naming this account, oldest first, as stored in PostgreSQL.</summary>
    public async Task<List<AuditEvent>> AuditEventsAsync(string account)
    {
        var dbFactory = _factory.Services.GetRequiredService<IDbContextFactory<SigyllDbContext>>();
        await using var db = await dbFactory.CreateDbContextAsync();
        return await db.AuditEvents.AsNoTracking()
            .Where(e => e.Actor == account || e.EntityName == account)
            .OrderBy(e => e.Id)
            .ToListAsync();
    }
}
