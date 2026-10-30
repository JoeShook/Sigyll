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
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Data;
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
public sealed partial class SigyllApp : IAsyncLifetime
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
        await ApplySchemaAsync(_postgres.GetConnectionString());

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
    public async Task ExecuteSqlAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(_postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

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

    /// <summary>
    /// Fills in and submits the form on <paramref name="page"/> named <paramref name="formName"/>, as a browser does:
    /// its hidden fields (antiforgery token, form name) plus the given ones. Returns the page the browser ends on.
    /// </summary>
    public static async Task<Page> SubmitAsync(
        HttpClient browser, string page, string formName, IReadOnlyDictionary<string, string> fields)
    {
        var html = await browser.GetStringAsync(page);
        var form = Forms().Matches(html).FirstOrDefault(f => HiddenFields(f.Value).GetValueOrDefault("_handler") == formName)
            ?? throw new InvalidOperationException($"No form '{formName}' on {page}.");
        var values = HiddenFields(form.Value);
        foreach (var (name, value) in fields)
            values[name] = value;
        return await PostAsync(browser, page, values);
    }

    /// <summary>Posts to <paramref name="url"/> with the antiforgery token of <paramref name="tokenPage"/>.</summary>
    public static async Task<Page> PostWithTokenAsync(
        HttpClient browser, string tokenPage, string url, IReadOnlyDictionary<string, string> fields)
    {
        var html = await browser.GetStringAsync(tokenPage);
        var values = new Dictionary<string, string>(fields)
        {
            ["__RequestVerificationToken"] = HiddenFields(html)["__RequestVerificationToken"],
        };
        return await PostAsync(browser, url, values);
    }

    public static async Task<Page> GetAsync(HttpClient browser, string url)
    {
        var response = await browser.GetAsync(url);
        return new Page(response.StatusCode, response.RequestMessage!.RequestUri!, await response.Content.ReadAsStringAsync());
    }

    private static async Task<Page> PostAsync(HttpClient browser, string url, Dictionary<string, string> values)
    {
        var response = await browser.PostAsync(url, new FormUrlEncodedContent(values));
        return new Page(response.StatusCode, response.RequestMessage!.RequestUri!, await response.Content.ReadAsStringAsync());
    }

    private static Dictionary<string, string> HiddenFields(string html)
    {
        var fields = new Dictionary<string, string>();
        foreach (Match input in Inputs().Matches(html))
        {
            var tag = input.Value;
            if (!tag.Contains("type=\"hidden\"", StringComparison.OrdinalIgnoreCase))
                continue;
            if (Attribute("name").Match(tag) is { Success: true } name)
                fields.TryAdd(WebUtility.HtmlDecode(name.Groups[1].Value),
                    WebUtility.HtmlDecode(Attribute("value").Match(tag) is { Success: true } v ? v.Groups[1].Value : ""));
        }
        return fields;
    }

    private static Regex Attribute(string name) => new($"""\b{name}="([^"]*)" """.TrimEnd());

    [GeneratedRegex("<form\\b.*?</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex Forms();

    [GeneratedRegex("<input\\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex Inputs();

    /// <summary>Runs the Flyway scripts in version order, as the sigil-flyway resource does.</summary>
    private static async Task ApplySchemaAsync(string connectionString)
    {
        var scripts = Directory.GetFiles(FindSchemaDirectory(), "V*__*.sql")
            .OrderBy(path => int.Parse(Path.GetFileName(path)[1..Path.GetFileName(path).IndexOf("__", StringComparison.Ordinal)]));

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using (var create = new NpgsqlCommand("CREATE SCHEMA IF NOT EXISTS sigil", connection))
            await create.ExecuteNonQueryAsync();
        foreach (var script in scripts)
        {
            var sql = (await File.ReadAllTextAsync(script)).Replace("${flyway:defaultSchema}", "sigil");
            await using var command = new NpgsqlCommand($"SET search_path TO sigil;\n{sql}", connection);
            await command.ExecuteNonQueryAsync();
        }
    }

    private static string FindSchemaDirectory()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "dist", "AlloyDB", "sigil", "sigil", "tables");
            if (Directory.Exists(candidate))
                return candidate;
        }
        throw new DirectoryNotFoundException("dist/AlloyDB/sigil/sigil/tables not found above the test output.");
    }
}

/// <summary>Where a request ended up, after redirects, and what it showed.</summary>
public sealed record Page(HttpStatusCode Status, Uri Url, string Html)
{
    public string PathAndQuery => Url.PathAndQuery;
}
