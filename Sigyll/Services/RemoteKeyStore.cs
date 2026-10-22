#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Services.Signing;
using Sigyll.Gcp;
using Sigyll.Vault;

namespace Sigyll.Services;

/// <summary>Destroys Vault Transit and GCP KMS keys named by a certificate's store-provider hint.</summary>
public class RemoteKeyStore : IRemoteKeyStore
{
    private const string VaultPrefix = "vault-transit:";
    private const string GcpPrefix = "gcp-kms:";

    private readonly VaultTransitSigningProvider _vault;
    private readonly GcpKmsSigningProvider _gcp;

    public RemoteKeyStore(VaultTransitSigningProvider vault, GcpKmsSigningProvider gcp)
    {
        _vault = vault;
        _gcp = gcp;
    }

    public async Task DestroyKeyAsync(string? storeProviderHint, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(storeProviderHint))
            return;

        if (storeProviderHint.StartsWith(VaultPrefix, StringComparison.Ordinal))
        {
            var keyName = storeProviderHint[VaultPrefix.Length..];
            if (keyName.Length > 0)
                await _vault.DeleteKeyAsync(keyName, ct);
        }
        else if (storeProviderHint.StartsWith(GcpPrefix, StringComparison.Ordinal))
        {
            var keyId = storeProviderHint[GcpPrefix.Length..];
            if (keyId.Length > 0)
                await _gcp.DestroyKeyVersionAsync(keyId, ct);
        }
    }
}
