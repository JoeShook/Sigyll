#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.Caching.Memory;
using Sigyll.Contracts;

namespace Sigyll.Portal.Services;

/// <summary>
/// Caches the CA's issuance catalog so the request wizard and policy engine don't hit the CA on
/// every render. The CA remains the source of truth; this is a short-lived read-through cache.
/// </summary>
public class CatalogService(CaApiClient ca, IMemoryCache cache, ILogger<CatalogService> logger)
{
    private const string CacheKey = "ra-catalog";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(2);

    public async Task<CatalogResponse> GetCatalogAsync(CancellationToken ct = default)
    {
        if (cache.TryGetValue(CacheKey, out CatalogResponse? cached) && cached is not null)
            return cached;

        try
        {
            var catalog = await ca.GetCatalogAsync(ct) ?? new CatalogResponse();
            cache.Set(CacheKey, catalog, Ttl);
            return catalog;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to fetch issuance catalog from the CA.");
            // Return an empty catalog rather than throwing so the UI can show a friendly message.
            return new CatalogResponse();
        }
    }

    public async Task<CatalogTemplate?> FindTemplateAsync(string name, CancellationToken ct = default)
    {
        var catalog = await GetCatalogAsync(ct);
        return catalog.Templates.FirstOrDefault(t =>
            string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    public void Invalidate() => cache.Remove(CacheKey);
}
