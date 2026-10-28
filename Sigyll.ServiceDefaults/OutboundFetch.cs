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
using System.Net.Sockets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Sigyll.ServiceDefaults;

/// <summary>
/// Limits on fetching URLs that come from untrusted input: AIA and CRL URLs written in certificates, and the
/// domains requesters ask to validate. Configuration section <c>OutboundFetch</c>.
/// </summary>
public sealed class OutboundFetchOptions
{
    /// <summary>Refuse private, loopback and carrier-grade NAT addresses unless the host is in <see cref="AllowedHosts"/>.</summary>
    public bool BlockPrivateAddresses { get; set; } = true;

    /// <summary>Host names that may resolve to private or loopback addresses: an exact name, or ".example.com" for its subdomains.</summary>
    public string[] AllowedHosts { get; set; } = [];

    /// <summary>Largest response body read, in bytes.</summary>
    public long MaxResponseBytes { get; set; } = 20 * 1024 * 1024;

    /// <summary>Redirects followed per request.</summary>
    public int MaxRedirects { get; set; } = 3;
}

/// <summary>Thrown when a fetch target resolves only to addresses the policy refuses.</summary>
public sealed class OutboundFetchBlockedException(string message) : Exception(message);

/// <summary>
/// HTTP clients for untrusted URLs. The address check runs when each connection is made, after DNS resolution and
/// for every redirect, so a host can't pass the check and then resolve somewhere else. Link-local addresses (cloud
/// metadata services), multicast and unspecified addresses are always refused; allow-listing a host can't override
/// that.
/// </summary>
public static class OutboundFetch
{
    public const string SectionName = "OutboundFetch";

    /// <summary>Registers a named client that fetches under the <c>OutboundFetch</c> configuration.</summary>
    public static IHttpClientBuilder AddOutboundFetchClient(this IServiceCollection services, string name, IConfiguration configuration)
    {
        var options = configuration.GetSection(SectionName).Get<OutboundFetchOptions>() ?? new OutboundFetchOptions();
        return services.AddHttpClient(name, client => client.MaxResponseContentBufferSize = options.MaxResponseBytes)
            .ConfigurePrimaryHttpMessageHandler(() => CreateHandler(options));
    }

    public static SocketsHttpHandler CreateHandler(OutboundFetchOptions options) => new()
    {
        // A proxy would make the connection, so the address check would only ever see the proxy.
        UseProxy = false,
        AllowAutoRedirect = options.MaxRedirects > 0,
        MaxAutomaticRedirections = Math.Max(1, options.MaxRedirects),
        PooledConnectionLifetime = TimeSpan.FromMinutes(1),
        ConnectCallback = (context, ct) => ConnectAsync(context.DnsEndPoint, options, ct),
    };

    private static async ValueTask<Stream> ConnectAsync(DnsEndPoint endPoint, OutboundFetchOptions options, CancellationToken ct)
    {
        var host = endPoint.Host;
        var addresses = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct);
        var blockPrivate = options.BlockPrivateAddresses && !IsAllowedHost(host, options.AllowedHosts);
        var permitted = addresses.Where(a => !IsRefused(a, blockPrivate)).ToArray();
        if (permitted.Length == 0)
            throw new OutboundFetchBlockedException(
                $"Refused to fetch from {host}: it resolves only to addresses Sigyll won't connect to "
                + $"({string.Join(", ", addresses.Select(a => a.ToString()))}). "
                + "A private or loopback host can be allowed in OutboundFetch:AllowedHosts.");

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(permitted, endPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public static bool IsAllowedHost(string host, IEnumerable<string> allowedHosts) =>
        allowedHosts.Any(allowed => !string.IsNullOrWhiteSpace(allowed) && (allowed.StartsWith('.')
            ? host.EndsWith(allowed, StringComparison.OrdinalIgnoreCase)
            : host.Equals(allowed, StringComparison.OrdinalIgnoreCase)));

    /// <summary>Whether an address is refused: always for link-local, multicast and unspecified; private ones when asked.</summary>
    public static bool IsRefused(IPAddress address, bool blockPrivate)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            if (b[0] == 169 && b[1] == 254) return true;                    // link-local, cloud metadata
            if (b[0] == 0 || b[0] >= 224) return true;                      // unspecified, multicast, reserved, broadcast
            if (!blockPrivate) return false;
            return b[0] == 10 || b[0] == 127                                // private, loopback
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)                // private
                || (b[0] == 192 && b[1] == 168)                             // private
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);              // carrier-grade NAT
        }

        if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.Equals(IPAddress.IPv6None)
            || address.Equals(IPAddress.IPv6Any)) return true;
        if (!blockPrivate) return false;
        return IPAddress.IsLoopback(address) || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal;
    }
}
