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
using Sigyll.Portal.Data;
using Sigyll.Portal.Data.Entities;
using Sigyll.Tests;
using Testcontainers.PostgreSql;

namespace Sigyll.Portal.Integration.Tests;

[CollectionDefinition(Name)]
public sealed class PortalAppCollection : ICollectionFixture<PortalApp>
{
    public const string Name = "Portal";
}

/// <summary>
/// The certificate request portal as it runs in production: its own startup (Program.cs), over PostgreSQL in Docker
/// with the schema the Flyway scripts in dist/AlloyDB build.
/// </summary>
public sealed class PortalApp : IAsyncLifetime
{
    public const string Password = "Correct-horse-battery-1";

    /// <summary>The first PortalAdmin, created at startup from configuration.</summary>
    public const string BootstrapAdmin = "portal-admin@example.test";

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17.6")
        .WithDatabase("portal")
        .Build();

    private WebApplicationFactory<Program> _factory = null!;

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        await FlywaySchema.ApplyAsync(_postgres.GetConnectionString(), "portal");

        // Program reads its configuration while registering services, so the settings go in as environment
        // variables, as a deployment's would.
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
        Environment.SetEnvironmentVariable("ConnectionStrings__PortalDb", _postgres.GetConnectionString());
        Environment.SetEnvironmentVariable("Auth__BootstrapAdmin__Email", BootstrapAdmin);
        Environment.SetEnvironmentVariable("Auth__BootstrapAdmin__Password", Password);
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

    /// <summary>
    /// A new confirmed account in <paramref name="roles"/> (none: a requester), with the authenticator app and
    /// passkeys if asked; returns its authenticator key.
    /// </summary>
    public async Task<string?> CreateUserAsync(
        string email, bool authenticator = false, int passkeys = 0, params string[] roles)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<PortalUser>>();
        var user = new PortalUser { UserName = email, Email = email, EmailConfirmed = true };
        (await users.CreateAsync(user, Password)).Succeeded.ShouldBeTrue();
        if (roles.Length > 0)
            (await users.AddToRolesAsync(user, roles)).Succeeded.ShouldBeTrue();
        for (var i = 0; i < passkeys; i++)
            (await users.AddOrUpdatePasskeyAsync(user, Passkey())).Succeeded.ShouldBeTrue();
        if (!authenticator)
            return null;
        await users.ResetAuthenticatorKeyAsync(user);
        await users.SetTwoFactorEnabledAsync(user, true);
        return await users.GetAuthenticatorKeyAsync(user);
    }

    /// <summary>Runs <paramref name="work"/> against the account <paramref name="email"/> with the portal's UserManager.</summary>
    public async Task<T> WithUserAsync<T>(string email, Func<UserManager<PortalUser>, PortalUser, Task<T>> work)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<PortalUser>>();
        return await work(users, (await users.FindByEmailAsync(email))!);
    }

    /// <summary>A passkey record, as a browser's registration would leave it (its keys are never used here).</summary>
    private static UserPasskeyInfo Passkey() => new(
        credentialId: Guid.NewGuid().ToByteArray(),
        publicKey: [1, 2, 3],
        createdAt: DateTimeOffset.UtcNow,
        signCount: 0,
        transports: ["internal"],
        isUserVerified: true,
        isBackupEligible: true,
        isBackedUp: true,
        attestationObject: [4],
        clientDataJson: [5]);

    public async Task<IReadOnlyList<string>> RecoveryCodesAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<PortalUser>>();
        return [.. (await users.GenerateNewTwoFactorRecoveryCodesAsync((await users.FindByEmailAsync(email))!, 10))!];
    }

    public async Task<PortalUser?> FindUserAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<PortalUser>>().FindByEmailAsync(email);
    }

    /// <summary>Runs SQL against the database directly, as someone with database access could.</summary>
    public Task ExecuteSqlAsync(string sql) => FlywaySchema.ExecuteAsync(_postgres.GetConnectionString(), sql);

    /// <summary>The audit trail's events naming this account, oldest first, as stored in PostgreSQL.</summary>
    public async Task<List<AuditEvent>> AuditEventsAsync(string account)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        return await db.AuditEvents.AsNoTracking()
            .Where(e => e.Actor == account || e.Account == account)
            .OrderBy(e => e.Id)
            .ToListAsync();
    }
}
