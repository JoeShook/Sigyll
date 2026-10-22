#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Eventing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace Sigyll.Vault.Hosting;

public static class VaultResourceBuilderExtensions
{
    private const string PersistentConfigJson = """
        {
          "storage": { "file": { "path": "/vault/file" } },
          "listener": { "tcp": { "address": "0.0.0.0:8200", "tls_disable": "true" } },
          "ui": true,
          "disable_mlock": true,
          "api_addr": "http://0.0.0.0:8200"
        }
        """;

    /// <summary>
    /// Adds a HashiCorp Vault container.
    /// </summary>
    /// <param name="builder">The Aspire app host builder.</param>
    /// <param name="name">Resource name.</param>
    /// <param name="rootToken">
    /// Well-known root token Sigyll uses to authenticate.
    /// In dev mode this is Vault's actual root token.
    /// In persistent mode this is created as an alias of Vault's randomly-generated root token after init.
    /// </param>
    /// <param name="port">Optional host port override; defaults to 8200.</param>
    /// <param name="persistent">
    /// false (default) = dev mode: in-memory storage, all keys lost on every restart.
    /// true = server mode: file-backed storage in a Docker volume, auto-init + auto-unseal,
    /// signing keys survive container restarts. Init state (root token + unseal keys) stored
    /// on the host filesystem at %LOCALAPPDATA%/Sigyll/vault-{name}-init.json.
    /// </param>
    public static IResourceBuilder<VaultResource> AddVaultDev(
        this IDistributedApplicationBuilder builder,
        string name,
        string rootToken = "root-token",
        int? port = null,
        bool persistent = false)
    {
        var resource = new VaultResource(name)
        {
            RootToken = rootToken,
            IsPersistent = persistent,
            HostInitStatePath = persistent ? VaultInitStateStore.GetDefaultPath(name) : null
        };

        var health = builder.Services.AddHealthChecks();

        var resourceBuilder = builder.AddResource(resource)
            .WithContainerName($"vault-{name}")
            .WithAnnotation(new ContainerImageAnnotation
            {
                Image = VaultContainerImageTags.Image,
                Tag = VaultContainerImageTags.Tag,
                Registry = VaultContainerImageTags.Registry
            })
            .WithContainerRuntimeArgs("--cap-add", "IPC_LOCK")
            .WithEndpoint(
                port ?? VaultResource.DefaultPort,
                VaultResource.DefaultPort,
                name: VaultResource.HttpEndpointName,
                scheme: "http");

        if (persistent)
        {
            // Server mode: file-backed storage, auto-init + auto-unseal handled by VaultServerConfigurator.
            // VAULT_LOCAL_CONFIG is read by the Vault entrypoint and written to /vault/config/local.json.
            resourceBuilder
                .WithEnvironment("VAULT_LOCAL_CONFIG", PersistentConfigJson)
                .WithArgs("server")
                .WithVolume($"vault-{name}-data", "/vault/file");
        }
        else
        {
            resourceBuilder
                .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", rootToken)
                .WithEnvironment("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200");
        }

        return resourceBuilder.WithHealthCheck(health, name, persistent);
    }

    /// <summary>
    /// Configures the Transit secrets engine with the specified signing keys.
    /// In dev mode, keys are recreated on every Vault start (Vault dev mode is in-memory).
    /// In persistent mode, also runs init + unseal + well-known root token alias before
    /// configuring Transit so the engine + keys are always available after a restart.
    /// </summary>
    public static IResourceBuilder<VaultResource> WithTransitEngine(
        this IResourceBuilder<VaultResource> builder,
        params TransitKeySpec[] keys)
    {
        builder.Resource.TransitKeys.AddRange(keys);
        return builder.WithConfigurationWatcher();
    }

    /// <summary>
    /// Configures this Vault (init + unseal in persistent mode, Transit keys, AppRole) each time it becomes ready.
    /// Runs inside Vault's ResourceReadyEvent, which resources that WaitFor(vault) wait on, so they start only once
    /// Vault is unsealed and configured. Subscribed once per resource, whichever of WithTransitEngine / WithAppRole
    /// is called first.
    /// </summary>
    internal static IResourceBuilder<VaultResource> WithConfigurationWatcher(this IResourceBuilder<VaultResource> builder)
    {
        if (builder.Resource.Annotations.OfType<VaultConfigurationWatcherAnnotation>().Any())
            return builder;

        builder.WithAnnotation(new VaultConfigurationWatcherAnnotation());
        builder.ApplicationBuilder.Eventing.Subscribe<ResourceReadyEvent>(builder.Resource,
            (@event, ct) => ConfigureAsync(builder.Resource, @event.Services, ct));

        return builder;
    }

    private sealed class VaultConfigurationWatcherAnnotation : IResourceAnnotation;

    private static async Task ConfigureAsync(VaultResource vault, IServiceProvider services, CancellationToken ct)
    {
        var logger = services.GetRequiredService<ILogger<VaultResource>>();
        // A failed earlier attempt (e.g. before a Vault restart) must not fail apps started after this one succeeds.
        if (vault.Configured.Task.IsFaulted)
            vault.Configured = new(TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var endpoint = vault.GetEndpoint(VaultResource.HttpEndpointName);
            var vaultAddress = $"http://localhost:{endpoint.Port}";

            if (vault.IsPersistent && vault.HostInitStatePath != null)
            {
                logger.LogInformation(
                    "Vault '{Name}' is reachable — ensuring init + unseal (persistent mode)",
                    vault.Name);
                await VaultServerConfigurator.EnsureVaultUsableAsync(
                    vaultAddress, vault.HostInitStatePath, vault.RootToken, logger, ct);
            }

            if (vault.TransitKeys.Count > 0)
            {
                logger.LogInformation(
                    "Vault '{Name}' is healthy — (re)configuring Transit engine",
                    vault.Name);
                await VaultTransitConfigurator.ConfigureTransitAsync(
                    vaultAddress, vault.RootToken, vault.TransitKeys, logger, ct);
            }

            if (vault.AppRole is not null)
            {
                await VaultAppRoleConfigurator.EnsureAsync(
                    vaultAddress, vault.RootToken, vault.Name, vault.AppRole, logger, ct);
            }

            vault.HostAddress = vaultAddress;
            vault.Configured.TrySetResult();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Failed to configure Vault for resource '{Name}'", vault.Name);
            vault.Configured.TrySetException(
                new InvalidOperationException($"Vault '{vault.Name}' could not be configured: {ex.Message}", ex));
        }
    }

    private static IResourceBuilder<VaultResource> WithHealthCheck(
        this IResourceBuilder<VaultResource> builder,
        IHealthChecksBuilder health,
        string name,
        bool persistent)
    {
        // In persistent mode, Vault starts uninitialized (501) then sealed (503). We pass
        // uninitcode=200&sealedcode=200 so the health endpoint reports 200 in those states,
        // letting Aspire mark the resource healthy while VaultServerConfigurator handles
        // init + unseal in the background.
        var healthQuery = persistent
            ? "?uninitcode=200&sealedcode=200&standbyok=true"
            : string.Empty;

        health.AddUrlGroup(
            _ => new Uri($"http://localhost:{VaultResource.DefaultPort}/v1/sys/health{healthQuery}"),
            $"{name}-vault-health",
            HealthStatus.Unhealthy);

        return builder.WithHealthCheck($"{name}-vault-health");
    }
}
