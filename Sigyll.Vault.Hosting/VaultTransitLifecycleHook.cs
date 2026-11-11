#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Sigyll.Vault.Hosting;

/// <summary>
/// Configures the Vault Transit secrets engine after the Vault container is healthy.
/// Called each time Vault becomes ready (ResourceReadyEvent).
/// </summary>
internal static class VaultTransitConfigurator
{
    private static readonly TimeSpan MoveTimeout = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Makes sure a Transit engine is mounted at <paramref name="mountPath"/> and holds <paramref name="keys"/>.
    /// When nothing is mounted there yet and a Transit engine exists at one of the <paramref name="moveFrom"/>
    /// paths (the first found, in order), that engine is moved to <paramref name="mountPath"/> with its keys; the
    /// key material stays inside Vault throughout.
    /// </summary>
    internal static async Task ConfigureTransitAsync(
        string vaultAddress,
        string rootToken,
        string mountPath,
        IReadOnlyList<string> moveFrom,
        List<TransitKeySpec> keys,
        ILogger logger,
        CancellationToken ct)
    {
        using var client = new HttpClient { BaseAddress = new Uri(vaultAddress) };
        client.DefaultRequestHeaders.Add("X-Vault-Token", rootToken);

        mountPath = mountPath.Trim('/');
        var mounts = await ReadMountsAsync(client, ct);

        // Vault refuses a mount nested in another ("transit" and "transit/sigyll" can't both exist), so a move
        // between such paths goes through this one. It is checked first, to finish a move that was interrupted.
        var stagingPath = mountPath.Replace('/', '-') + "-moving";
        var oldMount = moveFrom
            .Select(path => path.Trim('/'))
            .Prepend(stagingPath)
            .FirstOrDefault(path => path != mountPath && mounts.GetValueOrDefault(path) == "transit");
        var hasOldMount = oldMount is not null;

        if (mounts.TryGetValue(mountPath, out var mountedType))
        {
            if (mountedType != "transit")
            {
                throw new InvalidOperationException(
                    $"Vault has a '{mountedType}' engine at '{mountPath}', where Sigyll's Transit engine belongs.");
            }

            logger.LogInformation("Transit engine already mounted at {Mount}", mountPath);
            if (hasOldMount)
            {
                logger.LogWarning(
                    "Transit engines exist at both '{Mount}' and '{Old}'; Sigyll uses '{Mount}' and leaves '{Old}' alone.",
                    mountPath, oldMount, mountPath, oldMount);
            }
        }
        else if (hasOldMount)
        {
            if (IsNested(oldMount!, mountPath))
            {
                await MoveMountAsync(client, oldMount!, stagingPath, logger, ct);
                oldMount = stagingPath;
            }

            await MoveMountAsync(client, oldMount!, mountPath, logger, ct);
        }
        else
        {
            logger.LogInformation("Enabling Vault Transit engine at {Mount}", mountPath);
            using var mountResponse = await client.PostAsJsonAsync($"/v1/sys/mounts/{mountPath}", new { type = "transit" }, ct);
            await EnsureSuccessAsync(mountResponse, $"mount a Transit engine at '{mountPath}'", ct);
        }

        // Create signing keys (a key that already exists is left as it is).
        foreach (var key in keys)
        {
            logger.LogInformation("Ensuring Transit key '{Name}' (type: {Type})", key.Name, key.Type);

            using var keyResponse = await client.PostAsJsonAsync(
                $"/v1/{mountPath}/keys/{key.Name}",
                new { type = key.Type },
                ct);

            if (!keyResponse.IsSuccessStatusCode)
            {
                var body = await keyResponse.Content.ReadAsStringAsync(ct);
                logger.LogWarning("Transit key '{Name}' creation returned {Status}: {Body}",
                    key.Name, keyResponse.StatusCode, body);
            }
        }
    }

    /// <summary>
    /// Moves a secrets engine to another path (sys/remount). Vault runs the move in the background, so this waits
    /// for it to finish and then confirms the engine is at its new path. A failed move throws: carrying on would
    /// mount an empty engine and leave the existing keys behind.
    /// </summary>
    private static async Task MoveMountAsync(HttpClient client, string from, string to, ILogger logger, CancellationToken ct)
    {
        logger.LogInformation("Moving the Vault Transit engine from '{From}' to '{To}' (its keys move with it)", from, to);

        using var move = await client.PostAsJsonAsync("/v1/sys/remount", new { from, to }, ct);
        await EnsureSuccessAsync(move, $"move the Transit engine from '{from}' to '{to}'", ct);

        var migrationId = await ReadFieldAsync(move, ct, "migration_id");
        var deadline = DateTime.UtcNow + MoveTimeout;
        while (migrationId is not null)
        {
            using var status = await client.GetAsync($"/v1/sys/remount/status/{migrationId}", ct);
            await EnsureSuccessAsync(status, "read the progress of the Transit engine move", ct);
            var state = await ReadFieldAsync(status, ct, "migration_info", "status");
            if (state == "success") break;
            if (state == "failure" || DateTime.UtcNow > deadline)
            {
                throw new InvalidOperationException(
                    $"Vault did not finish moving the Transit engine from '{from}' to '{to}' (status: {state ?? "unknown"}).");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
        }

        var mounts = await ReadMountsAsync(client, ct);
        if (mounts.GetValueOrDefault(to) != "transit" || mounts.ContainsKey(from))
        {
            throw new InvalidOperationException(
                $"Vault reported the Transit engine moved from '{from}' to '{to}', but its mounts don't show it.");
        }

        logger.LogInformation("Vault Transit engine is now at '{To}'", to);
    }

    /// <summary>True when one mount path lies inside the other, which Vault does not allow to exist together.</summary>
    internal static bool IsNested(string a, string b) =>
        (b + "/").StartsWith(a + "/", StringComparison.Ordinal) || (a + "/").StartsWith(b + "/", StringComparison.Ordinal);

    /// <summary>The secrets engines mounted in Vault: path (no trailing slash) to engine type.</summary>
    private static async Task<Dictionary<string, string>> ReadMountsAsync(HttpClient client, CancellationToken ct)
    {
        using var response = await client.GetAsync("/v1/sys/mounts", ct);
        await EnsureSuccessAsync(response, "list the secrets engines", ct);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        var mounts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var mount in doc.RootElement.GetProperty("data").EnumerateObject())
        {
            if (mount.Value.ValueKind == JsonValueKind.Object && mount.Value.TryGetProperty("type", out var type))
            {
                mounts[mount.Name.Trim('/')] = type.GetString() ?? "";
            }
        }

        return mounts;
    }

    /// <summary>Reads a string at <paramref name="path"/>, whether Vault put it at the top level or under "data".</summary>
    private static async Task<string?> ReadFieldAsync(HttpResponseMessage response, CancellationToken ct, params string[] path)
    {
        var body = await response.Content.ReadAsStringAsync(ct);
        if (string.IsNullOrWhiteSpace(body)) return null;

        using var doc = JsonDocument.Parse(body);
        foreach (var root in new[] { doc.RootElement, doc.RootElement.TryGetProperty("data", out var data) ? data : default })
        {
            var current = root;
            var found = current.ValueKind == JsonValueKind.Object;
            foreach (var name in path)
            {
                found = found && current.ValueKind == JsonValueKind.Object && current.TryGetProperty(name, out current);
            }

            if (found && current.ValueKind == JsonValueKind.String) return current.GetString();
        }

        return null;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, string action, CancellationToken ct)
    {
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Vault: could not {action} ({(int)response.StatusCode}): {body}");
        }
    }
}
