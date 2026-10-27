#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Services.Export;

/// <summary>
/// The part of Vault's KV v2 API that exporting needs, called with the operator's own token so Vault's policies
/// decide what they can write.
/// </summary>
public interface IVaultKvClient
{
    /// <summary>The keys directly under <paramref name="path"/> (folders end in "/"); empty when there are none.</summary>
    Task<IReadOnlyList<string>> ListAsync(Uri address, string token, string mount, string path, CancellationToken ct = default);

    /// <summary>The field names of the secret at <paramref name="path"/>; empty when it doesn't exist.</summary>
    Task<IReadOnlyCollection<string>> ReadFieldNamesAsync(Uri address, string token, string mount, string path, CancellationToken ct = default);

    /// <summary>The fields of the secret at <paramref name="path"/> with their values; empty when it doesn't exist.</summary>
    Task<IReadOnlyDictionary<string, string>> ReadFieldsAsync(Uri address, string token, string mount, string path, CancellationToken ct = default);

    /// <summary>Deletes the secret at <paramref name="path"/> for good: every version and its metadata.</summary>
    Task DeleteAsync(Uri address, string token, string mount, string path, CancellationToken ct = default);

    /// <summary>
    /// Adds <paramref name="fields"/> to the secret at <paramref name="path"/>, keeping its other fields except
    /// <paramref name="remove"/>, and returns the new KV version. Creates the secret when it doesn't exist.
    /// </summary>
    Task<int> MergeAsync(
        Uri address, string token, string mount, string path,
        IReadOnlyDictionary<string, string> fields, IReadOnlyCollection<string>? remove = null, CancellationToken ct = default);
}

/// <summary>Vault refused the token: it expired, or its policies don't cover the path.</summary>
public class VaultTokenRefusedException(string path, int statusCode)
    : Exception($"Vault refused the token for {path} (HTTP {statusCode}): it expired, or its policies don't allow this path.")
{
    public string Path { get; } = path;
    public int StatusCode { get; } = statusCode;
}
