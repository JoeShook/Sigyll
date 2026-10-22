#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Vault;

/// <summary>
/// Configuration for connecting to Vault (section "Vault"): Transit signing and the key-password master key.
/// Authenticate with AppRole (<see cref="RoleId"/> + <see cref="SecretId"/>), or with a static <see cref="Token"/>.
/// </summary>
public class VaultTransitOptions
{
    /// <summary>
    /// Vault HTTP address, e.g. "http://localhost:8200".
    /// </summary>
    public string Address { get; set; } = "http://localhost:8200";

    /// <summary>
    /// Static token for Vault API calls. Ignored when <see cref="RoleId"/> and <see cref="SecretId"/> are set.
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// AppRole role id. With <see cref="SecretId"/>, Sigyll logs in at auth/{AppRoleMountPath}/login and renews
    /// its token by logging in again.
    /// </summary>
    public string RoleId { get; set; } = string.Empty;

    /// <summary>
    /// AppRole secret id.
    /// </summary>
    public string SecretId { get; set; } = string.Empty;

    /// <summary>
    /// Mount path of the AppRole auth method. Defaults to "approle".
    /// </summary>
    public string AppRoleMountPath { get; set; } = "approle";

    /// <summary>
    /// Mount path for the Transit engine. Defaults to "transit".
    /// </summary>
    public string MountPath { get; set; } = "transit";

    /// <summary>
    /// Mount path of the KV v2 engine holding the key-password master key. Defaults to "secret".
    /// </summary>
    public string KvMountPath { get; set; } = "secret";

    /// <summary>
    /// KV v2 secret holding the key-password master key, e.g. "sigyll/key-protection". Empty = not read from Vault.
    /// </summary>
    public string KeyProtectionPath { get; set; } = string.Empty;

    /// <summary>
    /// Field of the <see cref="KeyProtectionPath"/> secret holding the master key: base64 of 32 random bytes.
    /// </summary>
    public string KeyProtectionField { get; set; } = "master-key";

    public bool UsesAppRole => !string.IsNullOrWhiteSpace(RoleId) && !string.IsNullOrWhiteSpace(SecretId);

    public bool HasCredentials => UsesAppRole || !string.IsNullOrWhiteSpace(Token);
}
