#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.AppHost;
using Sigyll.Vault.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

// ── Vault ───────────────────────────────────────────────────────────────────
// Sigyll logs in to Vault with AppRole and reads its key-password master key from a KV v2 secret. Vault:Mode picks
// which Vault (appsettings.json; override in user secrets):
//   local    — this AppHost runs Vault (persistent: init state at %LOCALAPPDATA%/Sigyll/vault-vault-init.json, data
//              in the Docker volume vault-vault-data), creates the AppRole, policy and master key, and issues Sigyll
//              a new secret id on each start. Transit signing is available.
//   external — Sigyll logs in to an existing Vault: Vault:Address, plus the role id and secret id in the
//              Parameters:vault-role-id / Parameters:vault-secret-id user secrets. That Vault's AppRole needs read on
//              secret/data/<Vault:KeyProtectionPath>, and the master key (field "master-key", base64 of 32 random
//              bytes) is written there by its owner. Signing is local or GCP KMS; Transit is not offered.
var vaultConfig = builder.Configuration.GetSection("Vault");
var externalVault = string.Equals(vaultConfig["Mode"], "external", StringComparison.OrdinalIgnoreCase);
var keyProtectionPath = vaultConfig["KeyProtectionPath"] ?? "sigyll/key-protection";

IResourceBuilder<VaultResource>? vault = null;
if (!externalVault)
{
    vault = builder.AddVaultDev("vault", persistent: true)
        .WithTransitEngine(
            new TransitKeySpec("sigil-rsa-4096", "rsa-4096"),
            new TransitKeySpec("sigil-ecdsa-p384", "ecdsa-p384"))
        .WithAppRole(vaultConfig["RoleName"] ?? "sigyll", keyProtectionPath);
}

var vaultRoleId = externalVault ? builder.AddParameter("vault-role-id", secret: true) : null;
var vaultSecretId = externalVault ? builder.AddParameter("vault-secret-id", secret: true) : null;

IResourceBuilder<T> WithSigyllVault<T>(IResourceBuilder<T> app, string signingProvider)
    where T : IResourceWithEnvironment, IResourceWithWaitSupport
{
    if (vault is not null)
    {
        return app.WithReference(vault)
            .WithVaultAppRole(vault)
            .WithEnvironment("Signing__Provider", signingProvider)
            .WithEnvironment("Signing__AvailableProviders__0", "local")
            .WithEnvironment("Signing__AvailableProviders__1", "vault-transit");
    }

    return app
        .WithEnvironment("Vault__Address", vaultConfig["Address"] ?? "")
        .WithEnvironment("Vault__RoleId", vaultRoleId!)
        .WithEnvironment("Vault__SecretId", vaultSecretId!)
        .WithEnvironment("Vault__KeyProtectionPath", keyProtectionPath)
        .WithEnvironment("Signing__Provider", signingProvider == "vault-transit" ? "local" : signingProvider)
        .WithEnvironment("Signing__AvailableProviders__0", "local");
}

// Certificate server (static file host for CRLs and certs — always runs as a project)
var certServer = builder.AddProject<Projects.Sigyll_Certificate_Server>("certificate-server");

// ── PostgreSQL ──────────────────────────────────────────────────────────────
// A persistent container, created on first run or reused when one with the same name and spec is running.
// Name, volume, image tag and the shared-container version stamp come from appsettings.json and can be
// overridden in user secrets to share a Postgres other projects already run (dist/AlloyDB/README.md).
// The password parameter (Parameters:postgres-password) is generated on first run and kept in user secrets;
// to share an existing container, set it to that container's password.
var pg = builder.Configuration.GetSection("Postgres");
var pgContainer = pg["ContainerName"] ?? "sigyll-postgres";
var postgres = builder.AddPostgres("postgres")
    .WithImageTag(pg["ImageTag"] ?? "17.6")
    .WithContainerName(pgContainer)
    .WithDataVolume(pg["DataVolume"] ?? "sigyll-postgres-data")
    .WithLifetime(ContainerLifetime.Persistent)
    .WithSharedAspireVersion(pgContainer, pg["AspireVersionVariable"]);

var sigilDb = postgres.AddDatabase("sigil-db", databaseName: "sigil");
var portalDb = postgres.AddDatabase("portal-db", databaseName: "portal");

// ── Schemas (Flyway) ────────────────────────────────────────────────────────
// dist/AlloyDB/<db>/<schema>. Each runs once per AppHost start, before its app; after adding a V file,
// restart the flyway resource, then rebuild the app (a rebuild alone does not run new migrations).
IResourceBuilder<ContainerResource> AddFlyway(string database, IResourceBuilder<PostgresDatabaseResource> db) =>
    builder.AddContainer($"{database}-flyway", "flyway/flyway", "10")
        .WithParentRelationship(db)
        .WithBindMount(Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "..", "dist", "AlloyDB", database, database)),
            "/flyway/sql", isReadOnly: true)
        // The Postgres container answers to its resource name on the network Aspire puts both containers on.
        .WithEnvironment("FLYWAY_URL", $"jdbc:postgresql://{postgres.Resource.Name}:5432/{database}")
        .WithEnvironment("FLYWAY_USER", "postgres")
        .WithEnvironment(ctx => ctx.EnvironmentVariables["FLYWAY_PASSWORD"] = postgres.Resource.PasswordParameter)
        .WithEnvironment("FLYWAY_SCHEMAS", database)
        .WithEnvironment("FLYWAY_DEFAULT_SCHEMA", database)
        .WithEnvironment("FLYWAY_LOCATIONS", "filesystem:/flyway/sql")
        // A database created by EF migrations (before Flyway) is adopted at V1 instead of recreated.
        .WithEnvironment("FLYWAY_BASELINE_ON_MIGRATE", "true")
        .WithEnvironment("FLYWAY_BASELINE_VERSION", "1")
        .WithEnvironment("FLYWAY_VALIDATE_ON_MIGRATE", "false")
        .WithEnvironment("FLYWAY_OUT_OF_ORDER", "true")
        // Rides out PostgreSQL still starting when the AppHost comes up.
        .WithEnvironment("FLYWAY_CONNECT_RETRIES", "10")
        .WithArgs("migrate")
        .WaitFor(db);
var sigilFlyway = AddFlyway("sigil", sigilDb);
var portalFlyway = AddFlyway("portal", portalDb);

// Sigyll hosting mode: "project" (default), "docker", or "docker-gcp"
// Set via env var Sigyll__HostMode in launch profile.
var hostMode = builder.Configuration["Sigyll:HostMode"]?.ToLowerInvariant() ?? "project";

// Signing provider: "vault-transit" (default) or "gcp-kms"
// When "gcp-kms", Vault is still started (may be used for other keys) but Sigyll signs via GCP Cloud KMS.
var signingProvider = builder.Configuration["Sigyll:SigningProvider"]?.ToLowerInvariant() ?? "vault-transit";

IResourceBuilder<IResourceWithEndpoints> sigil;

switch (hostMode)
{
    case "docker-gcp":
    case "docker":
    {
        var dockerfile = hostMode == "docker-gcp" ? "Sigyll/Dockerfile.gcp" : "Sigyll/Dockerfile";

        var dockerResource = builder.AddDockerfile("sigil", "..", dockerfile)
            .WithHttpEndpoint(port: 5200, targetPort: 5200)
            .WithHttpsEndpoint(port: 7200, targetPort: 7200)
            .WithHttpsCertificateConfiguration(ctx =>
            {
                // Aspire injects its trusted dev cert — Kestrel picks it up via these env vars
                if (ctx.Password is null)
                {
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Path"] = ctx.CertificatePath;
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__KeyPath"] = ctx.KeyPath;
                }
                else
                {
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Path"] = ctx.PfxPath;
                    ctx.EnvironmentVariables["Kestrel__Certificates__Default__Password"] = ctx.Password;
                }
                return Task.CompletedTask;
            })
            .WithEnvironment("ASPNETCORE_URLS", "https://+:7200;http://+:5200")
            .WithReference(sigilDb, connectionName: "SigyllDb");
        WithSigyllVault(dockerResource, signingProvider);

        if (hostMode == "docker-gcp")
            dockerResource.WithVolume("sigil-gcloud-config", "/home/app/.config/gcloud");

        // GCP KMS configuration — project/location/keyring passed via env vars
        if (signingProvider == "gcp-kms")
        {
            var gcpProject = builder.Configuration["GcpKms:ProjectId"] ?? "";
            var gcpLocation = builder.Configuration["GcpKms:LocationId"] ?? "us-central1";
            var gcpKeyRing = builder.Configuration["GcpKms:KeyRingId"] ?? "sigil";

            dockerResource
                .WithEnvironment("GcpKms__ProjectId", gcpProject)
                .WithEnvironment("GcpKms__LocationId", gcpLocation)
                .WithEnvironment("GcpKms__KeyRingId", gcpKeyRing);
        }

        sigil = dockerResource.WaitForCompletion(sigilFlyway);
        break;
    }

    default: // "project"
        var projectResource = builder.AddProject<Projects.Sigyll>("sigil")
            .WithReference(sigilDb, connectionName: "SigyllDb");
        WithSigyllVault(projectResource, signingProvider);

        // GCP KMS configuration for project mode
        if (signingProvider == "gcp-kms")
        {
            var gcpProject = builder.Configuration["GcpKms:ProjectId"] ?? "";
            var gcpLocation = builder.Configuration["GcpKms:LocationId"] ?? "us-central1";
            var gcpKeyRing = builder.Configuration["GcpKms:KeyRingId"] ?? "sigil";

            projectResource
                .WithEnvironment("GcpKms__ProjectId", gcpProject)
                .WithEnvironment("GcpKms__LocationId", gcpLocation)
                .WithEnvironment("GcpKms__KeyRingId", gcpKeyRing);
        }

        sigil = projectResource.WaitForCompletion(sigilFlyway);
        break;
}

// Certificate request portal (isolated RA). True RA/CA split: the portal holds no CA keys and
// reaches the CA only via the internal RA API. CaBaseUrl is wired to the running CA endpoint;
// the dev RA API key matches the CA's "Ra:ApiKey". The portal uses its own 'portal' database.
builder.AddProject<Projects.Sigyll_Portal>("portal")
    .WithReference(portalDb, connectionName: "PortalDb")
    .WithEnvironment("Portal__CaBaseUrl", sigil.GetEndpoint("https"))
    .WithEnvironment("Portal__UseMtls", "false")
    .WithEnvironment("Portal__RaApiKey", "dev-ra-key-change-me")
    .WaitForCompletion(portalFlyway)
    .WaitFor(sigil);

builder.Build().Run();
