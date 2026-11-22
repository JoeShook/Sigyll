#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;

namespace Sigyll.Common.Services.Tefca;

/// <summary>Configuration for the TEFCA conformance check (configuration section <c>TefcaConformance</c>).</summary>
public sealed class TefcaConformanceSettings
{
    public const string SectionName = "TefcaConformance";

    /// <summary>
    /// The query parameter name that carries the exchange purpose in a client SAN URI (<c>?{name}=T-TRTMNT</c>),
    /// compared case-sensitively. No default: unset, only the fragment and last-path-segment forms are recognized.
    /// </summary>
    public string? ExchangePurposeQueryParameter { get; set; }
}

/// <summary>
/// Runs <see cref="TefcaConformanceChecker"/> on a certificate stored in Sigyll: an end-entity certificate issued here
/// or imported, with its issuing chain taken from the stored CAs.
/// </summary>
public class TefcaConformanceService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IOperatorContext _operator;
    private readonly IUrlReachabilityProbe? _probe;
    private readonly string? _queryParameter;

    public TefcaConformanceService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        IOperatorContext operatorContext,
        IUrlReachabilityProbe? probe = null,
        IOptions<TefcaConformanceSettings>? settings = null)
    {
        _dbFactory = dbFactory;
        _operator = operatorContext;
        _probe = probe;
        _queryParameter = settings?.Value.ExchangePurposeQueryParameter;
    }

    /// <summary>Whether CDP/AIA reachability can be probed (a probe is configured).</summary>
    public bool CanProbeReachability => _probe != null;

    /// <summary>
    /// Whether <paramref name="profile"/> issues TEFCA certificates, so its certificates are checked after
    /// issuance. A profile is TEFCA when its name contains "TEFCA" (any case).
    /// </summary>
    public static bool IsTefcaProfile(CertificateProfile? profile) =>
        profile?.Name?.Contains("TEFCA", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>
    /// Checks the stored end-entity certificate <paramref name="issuedCertificateId"/>. With
    /// <paramref name="probeReachability"/> and a configured probe, every CDP and AIA URL is fetched.
    /// Returns null when the certificate is not found.
    /// </summary>
    public async Task<IReadOnlyList<ConformanceCheckResult>?> CheckIssuedCertificateAsync(
        int issuedCertificateId, bool probeReachability = false, CancellationToken cancellationToken = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        return await CheckAsync(db, issuedCertificateId,
            new TefcaConformanceOptions
            {
                ReachabilityProbe = probeReachability ? _probe : null,
                ExchangePurposeQueryParameter = _queryParameter,
            }, cancellationToken);
    }

    /// <summary>The role a profile's certificate type implies: client, server, or unknown for no profile.</summary>
    public static TefcaCertificateRole RoleOf(CertificateType? type) => type switch
    {
        CertificateType.EndEntityClient => TefcaCertificateRole.Client,
        CertificateType.EndEntityServer => TefcaCertificateRole.Server,
        _ => TefcaCertificateRole.Unknown,
    };

    /// <summary>
    /// Loads the end-entity certificate and its stored issuing chain (nearest first) and checks it. Used by
    /// issuance, which has already checked the operator. Returns null when the certificate is not found.
    /// </summary>
    internal static async Task<IReadOnlyList<ConformanceCheckResult>?> CheckAsync(
        SigyllDbContext db, int issuedCertificateId, TefcaConformanceOptions options, CancellationToken cancellationToken = default)
    {
        var issued = await db.IssuedCertificates.AsNoTracking()
            .Where(c => c.Id == issuedCertificateId)
            .Select(c => new
            {
                c.X509CertificatePem,
                c.IssuingCaCertificateId,
                ProfileType = c.Profile == null ? (CertificateType?)null : c.Profile.CertificateType,
            })
            .FirstOrDefaultAsync(cancellationToken);
        if (issued == null)
            return null;

        if (options.Role == TefcaCertificateRole.Unknown)
            options = new TefcaConformanceOptions
            {
                Environment = options.Environment,
                Role = RoleOf(issued.ProfileType),
                ExchangePurposeQueryParameter = options.ExchangePurposeQueryParameter,
                SanFormatRule = options.SanFormatRule,
                ReachabilityProbe = options.ReachabilityProbe,
            };

        using var leaf = X509Certificate2.CreateFromPem(issued.X509CertificatePem);
        var issuers = new List<X509Certificate2>();
        try
        {
            int? nextId = issued.IssuingCaCertificateId;
            var seen = new HashSet<int>();
            while (nextId is int id && seen.Add(id) && seen.Count <= 16)
            {
                var ca = await db.CaCertificates.AsNoTracking()
                    .Where(c => c.Id == id)
                    .Select(c => new { c.X509CertificatePem, c.ParentId })
                    .FirstOrDefaultAsync(cancellationToken);
                if (ca == null)
                    break;
                issuers.Add(X509Certificate2.CreateFromPem(ca.X509CertificatePem));
                nextId = ca.ParentId;
            }

            return await TefcaConformanceChecker.CheckAsync(leaf, issuers, options, cancellationToken);
        }
        finally
        {
            foreach (var issuer in issuers)
                issuer.Dispose();
        }
    }
}

/// <summary>
/// Probes a CDP or AIA URL with an HTTP GET through a named <see cref="IHttpClientFactory"/> client.
/// </summary>
public sealed class HttpUrlReachabilityProbe : IUrlReachabilityProbe
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _clientName;

    public HttpUrlReachabilityProbe(IHttpClientFactory httpClientFactory, string clientName = "SigyllCrl")
    {
        _httpClientFactory = httpClientFactory;
        _clientName = clientName;
    }

    public async Task<string?> ProbeAsync(Uri url, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(Timeout);
        try
        {
            var client = _httpClientFactory.CreateClient(_clientName);
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            return response.IsSuccessStatusCode ? null : $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}";
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return $"no answer within {Timeout.TotalSeconds:0} seconds";
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException)
        {
            return ex.Message;
        }
    }
}
