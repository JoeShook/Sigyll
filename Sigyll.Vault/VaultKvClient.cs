#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sigyll.Common.Services.Export;

namespace Sigyll.Vault;

/// <summary>
/// Vault KV v2 over HTTP for exporting certificates, with the operator's token. A merge reads the secret, adds the
/// new fields and writes it back with check-and-set, so a concurrent write is retried rather than lost.
/// </summary>
public sealed class VaultKvClient : IVaultKvClient
{
    public const string HttpClientName = "VaultExport";

    private const int MaxAttempts = 3;
    private static readonly HttpMethod List = new("LIST");

    private readonly IHttpClientFactory _httpClientFactory;

    public VaultKvClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<IReadOnlyList<string>> ListAsync(Uri address, string token, string mount, string path, CancellationToken ct = default)
    {
        using var http = _httpClientFactory.CreateClient(HttpClientName);
        using var request = Request(List, address, token, $"{mount}/metadata/{path}");
        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return [];
        await EnsureSuccessAsync(response, path, ct);

        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        return doc.RootElement.TryGetProperty("data", out var data) && data.TryGetProperty("keys", out var keys)
            ? keys.EnumerateArray().Select(k => k.GetString()!).ToList()
            : [];
    }

    public async Task<IReadOnlyCollection<string>> ReadFieldNamesAsync(
        Uri address, string token, string mount, string path, CancellationToken ct = default)
    {
        using var http = _httpClientFactory.CreateClient(HttpClientName);
        var (fields, _) = await ReadAsync(http, address, token, mount, path, ct);
        return fields.Select(f => f.Key).ToList();
    }

    public async Task<int> MergeAsync(
        Uri address, string token, string mount, string path,
        IReadOnlyDictionary<string, string> fields, IReadOnlyCollection<string>? remove = null, CancellationToken ct = default)
    {
        using var http = _httpClientFactory.CreateClient(HttpClientName);
        for (var attempt = 1; ; attempt++)
        {
            var (current, version) = await ReadAsync(http, address, token, mount, path, ct);
            foreach (var name in remove ?? [])
                current.Remove(name);
            foreach (var (name, value) in fields)
                current[name] = value;

            using var request = Request(HttpMethod.Post, address, token, $"{mount}/data/{path}");
            var body = new JsonObject
            {
                ["options"] = new JsonObject { ["cas"] = version },
                ["data"] = current,
            };
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var response = await http.SendAsync(request, ct);

            // Someone else wrote the secret since we read it: read again and re-apply.
            if (response.StatusCode == HttpStatusCode.BadRequest && attempt < MaxAttempts
                && (await response.Content.ReadAsStringAsync(ct)).Contains("check-and-set", StringComparison.OrdinalIgnoreCase))
                continue;
            await EnsureSuccessAsync(response, path, ct);

            using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            return doc.RootElement.GetProperty("data").GetProperty("version").GetInt32();
        }
    }

    /// <summary>The secret's fields and version; version 0 when it has never been written.</summary>
    private static async Task<(JsonObject Fields, int Version)> ReadAsync(
        HttpClient http, Uri address, string token, string mount, string path, CancellationToken ct)
    {
        using var request = Request(HttpMethod.Get, address, token, $"{mount}/data/{path}");
        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode != HttpStatusCode.NotFound)
            await EnsureSuccessAsync(response, path, ct);

        // A deleted latest version also answers 404, with its metadata: check-and-set needs that version.
        var body = await response.Content.ReadAsStringAsync(ct);
        var root = string.IsNullOrWhiteSpace(body) ? null : JsonNode.Parse(body);
        var data = root?["data"];
        var version = data?["metadata"]?["version"]?.GetValue<int>() ?? 0;
        var fields = data?["data"] as JsonObject;
        return (fields == null ? new JsonObject() : (JsonObject)fields.DeepClone(), version);
    }

    private static HttpRequestMessage Request(HttpMethod method, Uri address, string token, string relativePath)
    {
        // Keep any path in the address (Vault behind a reverse proxy at /vault).
        var baseAddress = new Uri(address.AbsoluteUri.TrimEnd('/') + "/");
        var request = new HttpRequestMessage(method, new Uri(baseAddress, $"v1/{relativePath}"));
        request.Headers.Add("X-Vault-Token", token);
        return request;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, string path, CancellationToken ct)
    {
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new VaultTokenRefusedException(path, (int)response.StatusCode);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException(
                $"Vault answered HTTP {(int)response.StatusCode} for {path}: {body.Trim()}", null, response.StatusCode);
        }
    }
}
