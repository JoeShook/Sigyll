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
using Microsoft.Extensions.Options;

namespace Sigyll.Vault;

/// <summary>
/// Supplies the token for Vault API calls: an AppRole login, cached until shortly before its lease ends, or the
/// configured static token.
/// </summary>
public sealed class VaultTokenSource
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly VaultTransitOptions _options;
    private readonly ILogger<VaultTokenSource> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private string? _token;
    private DateTimeOffset _renewAt;

    public VaultTokenSource(
        IHttpClientFactory httpClientFactory,
        IOptions<VaultTransitOptions> options,
        ILogger<VaultTokenSource> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        if (!_options.UsesAppRole)
        {
            return _options.Token;
        }

        if (_token is not null && DateTimeOffset.UtcNow < _renewAt)
        {
            return _token;
        }

        await _gate.WaitAsync(ct);
        try
        {
            if (_token is null || DateTimeOffset.UtcNow >= _renewAt)
            {
                await LoginAsync(ct);
            }

            return _token!;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Forgets the cached token, e.g. after Vault answered 403, so the next call logs in again.</summary>
    public void Invalidate() => _token = null;

    /// <summary>A client for the Vault API, carrying the current token.</summary>
    public async Task<HttpClient> CreateClientAsync(CancellationToken ct = default)
    {
        var token = await GetTokenAsync(ct);
        var client = _httpClientFactory.CreateClient("VaultTransit");
        client.BaseAddress = new Uri(_options.Address);
        client.DefaultRequestHeaders.Remove("X-Vault-Token");
        client.DefaultRequestHeaders.Add("X-Vault-Token", token);
        return client;
    }

    private async Task LoginAsync(CancellationToken ct)
    {
        using var client = _httpClientFactory.CreateClient("VaultTransit");
        client.BaseAddress = new Uri(_options.Address);

        using var response = await client.PostAsJsonAsync(
            $"/v1/auth/{_options.AppRoleMountPath}/login",
            new { role_id = _options.RoleId, secret_id = _options.SecretId },
            ct);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException(
                $"Vault AppRole login failed ({(int)response.StatusCode}): {body}");
        }

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        var auth = doc.RootElement.GetProperty("auth");
        _token = auth.GetProperty("client_token").GetString()
            ?? throw new InvalidOperationException("Vault AppRole login returned no client token.");

        // Log in again at three quarters of the lease; a lease of 0 never expires.
        var lease = auth.TryGetProperty("lease_duration", out var leaseElement) ? leaseElement.GetInt32() : 0;
        _renewAt = lease > 0
            ? DateTimeOffset.UtcNow.AddSeconds(lease * 0.75)
            : DateTimeOffset.MaxValue;

        _logger.LogInformation("Logged in to Vault with AppRole (token lease {Lease}s)", lease);
    }
}
