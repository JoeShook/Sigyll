#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using Sigyll.Components.Account;
using Sigyll.Data;

namespace Sigyll.Auth.Tests;

/// <summary>
/// Operator Identity registered as the host registers it (<see cref="OperatorIdentityServices.AddOperatorIdentity"/>),
/// over an in-memory SQLite store (the in-memory EF provider can't read the passkeys' JSON column). Each <see cref="Request"/> is one HTTP request with its own scope; cookies the previous
/// request set can be carried into the next, as a browser would.
/// </summary>
internal sealed class TestIdentity : IAsyncDisposable
{
    public const string Password = "Correct-horse-battery-1";

    private readonly SqliteConnection _database;
    private readonly ServiceProvider _services;

    public TestIdentity(string environment = "Production", Dictionary<string, string?>? settings = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings ?? []).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment(environment));
        services.AddLogging();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddHttpContextAccessor();
        _database = OpenDatabase();
        services.AddDbContext<SigyllAuthDbContext>(options => options.UseSqlite(_database));
        services.AddOperatorIdentity(configuration);
        _services = services.BuildServiceProvider();
        CreateSchema(_services);
    }

    /// <summary>An in-memory SQLite database; it lives as long as the connection stays open.</summary>
    public static SqliteConnection OpenDatabase()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        return connection;
    }

    public static void CreateSchema(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<SigyllAuthDbContext>().Database.EnsureCreated();
    }

    /// <summary>Starts a request, carrying the cookies <paramref name="previous"/> set.</summary>
    public TestRequest Request(TestRequest? previous = null) => new(_services.CreateScope(), previous?.SetCookies ?? []);

    /// <summary>Creates an operator with the given second factors.</summary>
    public async Task<SigyllUser> CreateOperatorAsync(string email, bool authenticator = false, int passkeys = 0)
    {
        using var request = Request();
        var user = new SigyllUser { UserName = email, Email = email, EmailConfirmed = true };
        (await request.Users.CreateAsync(user, Password)).Succeeded.ShouldBeTrue();
        if (authenticator)
        {
            await request.Users.ResetAuthenticatorKeyAsync(user);
            await request.Users.SetTwoFactorEnabledAsync(user, true);
        }
        for (var i = 0; i < passkeys; i++)
            (await request.Users.AddOrUpdatePasskeyAsync(user, Passkey())).Succeeded.ShouldBeTrue();
        return user;
    }

    public static UserPasskeyInfo Passkey() => new(
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

    public async ValueTask DisposeAsync()
    {
        await _services.DisposeAsync();
        await _database.DisposeAsync();
    }

    internal sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "Sigyll";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}

internal sealed class TestRequest : IDisposable
{
    private readonly IServiceScope _scope;

    public TestRequest(IServiceScope scope, IReadOnlyList<SetCookieHeaderValue> carriedCookies)
    {
        _scope = scope;
        Http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        Http.Request.Scheme = "https";
        Http.Request.Host = new HostString("sigyll.test");
        if (carriedCookies.Count > 0)
            Http.Request.Headers.Cookie = string.Join("; ", carriedCookies.Select(c => $"{c.Name}={c.Value}"));
        scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = Http;
    }

    public HttpContext Http { get; }
    public UserManager<SigyllUser> Users => _scope.ServiceProvider.GetRequiredService<UserManager<SigyllUser>>();
    public SignInManager<SigyllUser> SignIn => _scope.ServiceProvider.GetRequiredService<SignInManager<SigyllUser>>();
    public OperatorSignIn OperatorSignIn => _scope.ServiceProvider.GetRequiredService<OperatorSignIn>();

    public async Task<SigyllUser> UserAsync(string email) => (await Users.FindByEmailAsync(email))!;

    /// <summary>Cookies this request set, as a browser would keep them.</summary>
    public IReadOnlyList<SetCookieHeaderValue> SetCookies =>
        SetCookieHeaderValue.ParseList(Http.Response.Headers.SetCookie.OfType<string>().ToList()).ToList();

    /// <summary>Whether this request signed the operator in (issued the session cookie).</summary>
    public bool StartedSession => SetCookies.Any(c =>
        c.Name.Value!.StartsWith($".AspNetCore.{IdentityConstants.ApplicationScheme}", StringComparison.Ordinal)
        && !string.IsNullOrEmpty(c.Value.Value));

    public void Dispose() => _scope.Dispose();
}
