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
using Sigyll.Pkcs11;
using Sigyll.Vault;

namespace Sigyll.Services;

/// <summary>Destroys Vault Transit, GCP KMS and PKCS #11 keys named by a certificate's store-provider hint.</summary>
public class RemoteKeyStore : IRemoteKeyStore
{
    private const string VaultPrefix = "vault-transit:";
    private const string GcpPrefix = "gcp-kms:";
    private const string Pkcs11Prefix = Pkcs11SigningProvider.Name + ":";

    private readonly VaultTransitSigningProvider _vault;
    private readonly GcpKmsSigningProvider _gcp;
    private readonly Pkcs11SigningProvider _pkcs11;

    public RemoteKeyStore(VaultTransitSigningProvider vault, GcpKmsSigningProvider gcp, Pkcs11SigningProvider pkcs11)
    {
        _vault = vault;
        _gcp = gcp;
        _pkcs11 = pkcs11;
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
        else if (storeProviderHint.StartsWith(Pkcs11Prefix, StringComparison.Ordinal))
        {
            var label = storeProviderHint[Pkcs11Prefix.Length..];
            if (label.Length > 0)
                await _pkcs11.DestroyKeyAsync(label, ct);
        }
    }
}
