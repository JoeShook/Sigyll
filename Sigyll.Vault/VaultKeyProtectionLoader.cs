#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.Extensions.Options;
using Sigyll.Common.Data;

namespace Sigyll.Vault;

/// <summary>
/// Reads the key-password master key from a Vault KV v2 secret (Vault:KeyProtectionPath).
/// </summary>
public sealed class VaultKeyProtectionLoader
{
    private readonly VaultTokenSource _tokens;
    private readonly VaultTransitOptions _options;

    public VaultKeyProtectionLoader(VaultTokenSource tokens, IOptions<VaultTransitOptions> options)
    {
        _tokens = tokens;
        _options = options.Value;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_options.KeyProtectionPath);

    /// <summary>The master key, or null when no Vault path is configured. Throws when it is configured but unreadable.</summary>
    public async Task<byte[]?> LoadAsync(CancellationToken ct = default)
    {
        if (!IsConfigured)
        {
            return null;
        }

        if (!_options.HasCredentials)
        {
            throw new InvalidOperationException(
                "Vault:KeyProtectionPath is set but there are no Vault credentials (Vault:RoleId + Vault:SecretId, or Vault:Token).");
        }

        var path = $"/v1/{_options.KvMountPath}/data/{_options.KeyProtectionPath.Trim('/')}";
        using var client = await _tokens.CreateClientAsync(ct);
        using var response = await client.GetAsync(path, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Could not read the key-password master key from Vault {path} ({(int)response.StatusCode}).");
        }

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        if (!doc.RootElement.GetProperty("data").GetProperty("data")
                .TryGetProperty(_options.KeyProtectionField, out var field) ||
            field.GetString() is not { Length: > 0 } value)
        {
            throw new InvalidOperationException(
                $"Vault secret {path} has no '{_options.KeyProtectionField}' field.");
        }

        return KeyPasswordProtection.ParseMasterKey(value);
    }
}
