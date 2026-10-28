using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.Extensions.Options;
using Sigyll.Portal.Components;
using Sigyll.Portal.Components.Account;
using Sigyll.Portal.Data;
using Sigyll.Portal.Services;
using Sigyll.ServiceDefaults;

var builder = WebApplication.CreateBuilder(args);

// Aspire service defaults (OTel, health checks, service discovery) when running under the AppHost.
var useServiceDefaults = builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] is not null;
if (useServiceDefaults)
{
    builder.AddServiceDefaults();
}

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddFluentUIComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddIdentityCookies();

var connectionString = builder.Configuration.GetConnectionString("PortalDb") ?? throw new InvalidOperationException("Connection string 'PortalDb' not found.");
builder.Services.AddDbContext<PortalDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentityCore<PortalUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true;
        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<PortalDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.AddAuthorization();

// Pin the passkey Relying Party ID explicitly. A CA must not infer the RP ID from the host
// header (credential-scoping risk) — see IdentityPasskeyOptions.ServerDomain guidance.
builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    options.ServerDomain = builder.Configuration["Portal:Passkey:ServerDomain"];
});

// Portal services: catalog (cached), classification policy, http-01 validation, CA client, workflow.
builder.Services.Configure<PortalOptions>(builder.Configuration.GetSection("Portal"));
builder.Services.AddMemoryCache();
// http-01 challenge URLs name the requester's host, so their fetches go through the outbound fetch policy.
builder.Services.AddOutboundFetchClient("dv", builder.Configuration);
builder.Services.AddHttpClient<CaApiClient>((sp, client) =>
    {
        var opts = sp.GetRequiredService<IOptions<PortalOptions>>().Value;
        if (!string.IsNullOrWhiteSpace(opts.CaBaseUrl))
            client.BaseAddress = new Uri(opts.CaBaseUrl);
    })
    .ConfigurePrimaryHttpMessageHandler(sp =>
    {
        var handler = new HttpClientHandler();
        var env = sp.GetRequiredService<IHostEnvironment>();
        var opts = sp.GetRequiredService<IOptions<PortalOptions>>().Value;
        // Dev convenience: accept the CA's local dev TLS cert. Production uses mTLS + real trust.
        if (env.IsDevelopment() && !opts.UseMtls)
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    });
builder.Services.AddScoped<CatalogService>();
builder.Services.AddSingleton<IssuancePolicyService>();
builder.Services.AddScoped<DomainValidationService>();
builder.Services.AddScoped<RequestWorkflowService>();

builder.Services.AddSingleton<IEmailSender<PortalUser>, IdentityNoOpEmailSender>();

builder.Services.AddHsts(options => options.MaxAge = TimeSpan.FromDays(365));

var app = builder.Build();

// Seed data. The schema is Flyway's (dist/AlloyDB/portal), applied before the portal starts.
using (var scope = app.Services.CreateScope())
{

    // Seed roles and dev accounts. Requesters only need to be authenticated (no role); RA/PortalAdmin
    // gate the RA queue. Passkeys can be enrolled after first sign-in under Account → Manage.
    var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "Requester", "RA", "PortalAdmin" })
        if (!await roleMgr.RoleExistsAsync(role))
            await roleMgr.CreateAsync(new IdentityRole(role));

    var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<PortalUser>>();
    await SeedUserAsync(userMgr, "admin@sigyll.local", "Passw0rd!", "RA", "PortalAdmin");
    await SeedUserAsync(userMgr, "requester@sigyll.local", "Passw0rd!");
}

static async Task SeedUserAsync(UserManager<PortalUser> userMgr, string email, string password, params string[] roles)
{
    if (await userMgr.FindByEmailAsync(email) is not null) return;
    var user = new PortalUser
    {
        UserName = email,
        Email = email,
        EmailConfirmed = true,
        DisplayName = email.Split('@')[0],
    };
    var result = await userMgr.CreateAsync(user, password);
    if (result.Succeeded && roles.Length > 0)
        await userMgr.AddToRolesAsync(user, roles);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();
app.UseSecurityHeaders();

app.UseAntiforgery();

if (useServiceDefaults)
{
    app.MapDefaultEndpoints(); // Aspire health checks (/health, /alive)
}

app.MapStaticAssets();
app.MapRazorComponents<App>()
    // Blazor sends its own frame-ancestors policy ('self' by default); match the app's: never framed.
    .AddInteractiveServerRenderMode(options => options.ContentSecurityFrameAncestorsPolicy = "'none'");

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

// Authenticated download of an issued certificate / chain (requester-owned only).
app.MapGet("/requests/{id:int}/download/cert", async (int id, HttpContext http, PortalDbContext db) =>
{
    var userId = http.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var r = await db.CertificateRequests.FindAsync(id);
    if (r is null || r.RequesterId != userId || string.IsNullOrEmpty(r.CertificatePem))
        return Results.NotFound();
    return Results.File(Encoding.UTF8.GetBytes(r.CertificatePem), "application/x-pem-file", $"request-{id}.cer");
}).RequireAuthorization();

app.MapGet("/requests/{id:int}/download/chain", async (int id, HttpContext http, PortalDbContext db) =>
{
    var userId = http.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var r = await db.CertificateRequests.FindAsync(id);
    if (r is null || r.RequesterId != userId || string.IsNullOrEmpty(r.ChainPem))
        return Results.NotFound();
    return Results.File(Encoding.UTF8.GetBytes(r.ChainPem), "application/x-pem-file", $"request-{id}-chain.pem");
}).RequireAuthorization();

app.Run();
