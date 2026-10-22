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
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Logging;

namespace Sigyll.Vault.Hosting;

/// <summary>
/// An AppRole the AppHost creates in its Vault for an app, and the KV v2 secret holding the app's key-password
/// master key. The app logs in with the role id and a secret id instead of the root token.
/// </summary>
/// <param name="RoleName">AppRole name; also the name of its policy.</param>
/// <param name="KeyProtectionPath">KV v2 secret under secret/ holding the master key, e.g. "sigyll/key-protection".</param>
/// <param name="KeyProtectionField">Field of that secret: base64 of 32 random bytes.</param>
public sealed record VaultAppRoleSpec(string RoleName, string KeyProtectionPath, string KeyProtectionField = "master-key");

/// <summary>AppRole credentials issued to an app.</summary>
internal sealed record VaultAppRoleCredentials(string RoleId, string SecretId);

public static class VaultAppRoleExtensions
{
    /// <summary>
    /// Creates an AppRole for an app once Vault is usable: a policy allowing it to read its key-password master key and
    /// to use Transit, the role, and the master key itself when the secret does not exist yet. The master key is also
    /// kept beside the init state (%LOCALAPPDATA%/Sigyll/vault-{name}-master-key.txt) and written back to Vault when
    /// Vault has lost it, so a dev-mode restart or a deleted volume does not strand encrypted key passwords.
    /// </summary>
    public static IResourceBuilder<VaultResource> WithAppRole(
        this IResourceBuilder<VaultResource> builder,
        string roleName,
        string keyProtectionPath)
    {
        builder.Resource.AppRole = new VaultAppRoleSpec(roleName, keyProtectionPath.Trim('/'));
        return builder.WithConfigurationWatcher();
    }

    /// <summary>
    /// Gives an app the Vault address and AppRole credentials (Vault__Address, Vault__RoleId, Vault__SecretId) plus
    /// the location of its key-password master key. A new secret id is issued each time the app starts.
    /// </summary>
    public static IResourceBuilder<T> WithVaultAppRole<T>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<VaultResource> vault)
        where T : IResourceWithEnvironment, IResourceWithWaitSupport
    {
        var spec = vault.Resource.AppRole
            ?? throw new InvalidOperationException($"Call WithAppRole on Vault '{vault.Resource.Name}' first.");

        return builder
            .WaitFor(vault)
            .WithEnvironment("Vault__Address", vault.Resource.PrimaryEndpoint)
            .WithEnvironment("Vault__KeyProtectionPath", spec.KeyProtectionPath)
            .WithEnvironment("Vault__KeyProtectionField", spec.KeyProtectionField)
            .WithEnvironment(async ctx =>
            {
                if (ctx.ExecutionContext.IsPublishMode)
                {
                    return;
                }

                var credentials = await VaultAppRoleConfigurator.IssueCredentialsAsync(vault.Resource, ctx.CancellationToken);
                ctx.EnvironmentVariables["Vault__RoleId"] = credentials.RoleId;
                ctx.EnvironmentVariables["Vault__SecretId"] = credentials.SecretId;
            });
    }
}

internal static class VaultAppRoleConfigurator
{
    private static readonly TimeSpan ConfigureTimeout = TimeSpan.FromMinutes(3);

    public static async Task EnsureAsync(
        string vaultAddress, string rootToken, string vaultName, VaultAppRoleSpec spec, ILogger logger, CancellationToken ct)
    {
        using var client = new HttpClient { BaseAddress = new Uri(vaultAddress) };
        client.DefaultRequestHeaders.Add("X-Vault-Token", rootToken);

        using (var auth = await client.PostAsJsonAsync("/v1/sys/auth/approle", new { type = "approle" }, ct))
        {
            // 400 = already enabled
            if (!auth.IsSuccessStatusCode && auth.StatusCode != HttpStatusCode.BadRequest)
            {
                await ThrowAsync(auth, "enable AppRole auth", ct);
            }
        }

        var policy = $$"""
            path "secret/data/{{spec.KeyProtectionPath}}" { capabilities = ["read"] }
            path "transit/keys/*" { capabilities = ["create", "read", "update", "delete"] }
            path "transit/sign/*" { capabilities = ["update"] }
            """;
        using (var put = await client.PutAsJsonAsync($"/v1/sys/policies/acl/{spec.RoleName}", new { policy }, ct))
        {
            await EnsureSuccessAsync(put, $"write policy '{spec.RoleName}'", ct);
        }

        var role = new
        {
            token_policies = new[] { spec.RoleName },
            token_ttl = "1h",
            token_max_ttl = "4h",
            secret_id_ttl = "0",
        };
        using (var post = await client.PostAsJsonAsync($"/v1/auth/approle/role/{spec.RoleName}", role, ct))
        {
            await EnsureSuccessAsync(post, $"write AppRole '{spec.RoleName}'", ct);
        }

        await EnsureMasterKeyAsync(client, vaultName, spec, logger, ct);
        logger.LogInformation("Vault AppRole '{Role}' ready", spec.RoleName);
    }

    public static async Task<VaultAppRoleCredentials> IssueCredentialsAsync(VaultResource vault, CancellationToken ct)
    {
        try
        {
            await vault.Configured.Task.WaitAsync(ConfigureTimeout, ct);
        }
        catch (TimeoutException)
        {
            throw new InvalidOperationException(
                $"Vault '{vault.Name}' was not configured within {ConfigureTimeout.TotalMinutes} minutes; see the AppHost log.");
        }

        var spec = vault.AppRole!;
        using var client = new HttpClient { BaseAddress = new Uri(vault.HostAddress!) };
        client.DefaultRequestHeaders.Add("X-Vault-Token", vault.RootToken);

        using var roleIdResponse = await client.GetAsync($"/v1/auth/approle/role/{spec.RoleName}/role-id", ct);
        await EnsureSuccessAsync(roleIdResponse, "read the role id", ct);
        var roleId = await ReadDataFieldAsync(roleIdResponse, "role_id", ct);

        using var secretIdResponse = await client.PostAsync($"/v1/auth/approle/role/{spec.RoleName}/secret-id", null, ct);
        await EnsureSuccessAsync(secretIdResponse, "issue a secret id", ct);
        var secretId = await ReadDataFieldAsync(secretIdResponse, "secret_id", ct);

        return new VaultAppRoleCredentials(roleId, secretId);
    }

    public static string GetMasterKeyBackupPath(string vaultName) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sigyll",
            $"vault-{vaultName}-master-key.txt");

    private static async Task EnsureMasterKeyAsync(
        HttpClient client, string vaultName, VaultAppRoleSpec spec, ILogger logger, CancellationToken ct)
    {
        var path = $"/v1/secret/data/{spec.KeyProtectionPath}";
        var backupPath = GetMasterKeyBackupPath(vaultName);
        var backup = File.Exists(backupPath) ? File.ReadAllText(backupPath).Trim() : null;

        using var read = await client.GetAsync(path, ct);
        if (read.IsSuccessStatusCode)
        {
            var stored = await ReadSecretFieldAsync(read, spec.KeyProtectionField, ct);
            if (backup is null && stored is not null)
            {
                SaveBackup(backupPath, stored);
                logger.LogInformation("Backed up the key-password master key to {Path}", backupPath);
            }
            else if (backup is not null && stored is not null && backup != stored)
            {
                logger.LogWarning(
                    "The key-password master key in Vault {Path} differs from the backup at {Backup}; keeping both as they are.",
                    path, backupPath);
            }

            if (stored is not null)
            {
                return;
            }
        }
        else if (read.StatusCode != HttpStatusCode.NotFound)
        {
            await ThrowAsync(read, $"read {path}", ct);
        }

        // Missing in Vault: restore the backup, or create a key (backed up before it is used).
        var key = backup ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        if (backup is null)
        {
            SaveBackup(backupPath, key);
        }

        var body = new Dictionary<string, object>
        {
            ["data"] = new Dictionary<string, string> { [spec.KeyProtectionField] = key },
        };
        using var write = await client.PostAsJsonAsync(path, body, ct);
        await EnsureSuccessAsync(write, $"write {path}", ct);
        logger.LogInformation(backup is null
            ? "Created the key-password master key in Vault {Path} (backup: {Backup})"
            : "Restored the key-password master key to Vault {Path} from {Backup}", path, backupPath);
    }

    private static void SaveBackup(string path, string key)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, key);
    }

    private static async Task<string?> ReadSecretFieldAsync(HttpResponseMessage response, string field, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        return doc.RootElement.GetProperty("data").GetProperty("data").TryGetProperty(field, out var value)
            ? value.GetString()
            : null;
    }

    private static async Task<string> ReadDataFieldAsync(HttpResponseMessage response, string field, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        return doc.RootElement.GetProperty("data").GetProperty(field).GetString()
            ?? throw new InvalidOperationException($"Vault returned no {field}.");
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, string action, CancellationToken ct)
    {
        if (!response.IsSuccessStatusCode)
        {
            await ThrowAsync(response, action, ct);
        }
    }

    private static async Task ThrowAsync(HttpResponseMessage response, string action, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct);
        throw new InvalidOperationException($"Vault: could not {action} ({(int)response.StatusCode}): {body}");
    }
}
