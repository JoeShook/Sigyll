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
using Microsoft.Extensions.Options;
using Sigyll.Contracts;

namespace Sigyll.Portal.Services;

/// <summary>
/// Typed HttpClient for the CA core's internal RA API. This is the only channel the portal uses to
/// reach the CA — it reads the issuance catalog and submits CSR-based issuance requests. The portal
/// holds no CA keys; the CA signs. Base address and auth are configured in DI from <see cref="PortalOptions"/>.
/// </summary>
public class CaApiClient(HttpClient http, IOptions<PortalOptions> options)
{
    private readonly PortalOptions _options = options.Value;

    /// <summary>Fetches the sanitized catalog of trust domains and templates from the CA.</summary>
    public async Task<CatalogResponse?> GetCatalogAsync(CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/ra/catalog");
        AddAuth(req);
        using var resp = await http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadFromJsonAsync<CatalogResponse>(ct);
    }

    /// <summary>Submits a CSR-based issuance request to the CA and returns the result.</summary>
    public async Task<IssuanceApiResult> IssueAsync(IssuanceApiRequest request, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/ra/issue")
        {
            Content = JsonContent.Create(request),
        };
        AddAuth(req);
        using var resp = await http.SendAsync(req, ct);
        var result = await resp.Content.ReadFromJsonAsync<IssuanceApiResult>(ct);
        return result ?? IssuanceApiResult.Failure($"CA returned {(int)resp.StatusCode} with no body.");
    }

    private void AddAuth(HttpRequestMessage req)
    {
        // mTLS (production) is configured on the HttpClient handler in DI. The dev fallback is the
        // shared API-key header.
        if (!_options.UseMtls && !string.IsNullOrEmpty(_options.RaApiKey))
            req.Headers.Add("X-RA-ApiKey", _options.RaApiKey);
    }
}
