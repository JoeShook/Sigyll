#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Data.Entities;

/// <summary>
/// Where certificates can be exported besides a file download: a HashiCorp Vault KV v2 mount. One row
/// (<see cref="SingletonId"/>), set by an Admin. Each trust domain picks its folder under the mount
/// (<see cref="TrustDomain.VaultNamespace"/>); the operator exporting supplies their own Vault token.
/// </summary>
public class VaultExportSettings
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    /// <summary>Whether the export buttons offer Vault next to the file download.</summary>
    public bool Enabled { get; set; }

    /// <summary>Vault server address, e.g. https://vault.example.org:8200.</summary>
    public string? Address { get; set; }

    /// <summary>The KV v2 secrets engine mount, usually "secret".</summary>
    public string Mount { get; set; } = "secret";

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>The operator who last changed these settings.</summary>
    public string? UpdatedBy { get; set; }
}
