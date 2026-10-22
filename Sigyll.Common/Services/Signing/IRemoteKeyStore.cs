#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Services.Signing;

/// <summary>
/// Destroys a key held by a remote signing backend (Vault Transit, GCP KMS). Only
/// <see cref="CertificateManagementService.DeleteAsync"/> calls it, after its permission check;
/// the host implements it because the backends live in projects Sigyll.Common does not reference.
/// </summary>
public interface IRemoteKeyStore
{
    /// <summary>
    /// Destroys the key named by a certificate's <c>StoreProviderHint</c>
    /// (<c>vault-transit:&lt;key&gt;</c> or <c>gcp-kms:&lt;key&gt;</c>). Does nothing for other hints.
    /// </summary>
    Task DestroyKeyAsync(string? storeProviderHint, CancellationToken ct = default);
}
