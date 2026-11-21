#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sigyll.Contracts;
using Sigyll.Portal.Data;
using Sigyll.Portal.Data.Entities;
using CertificateRequest = Sigyll.Portal.Data.Entities.CertificateRequest;

namespace Sigyll.Portal.Services;

/// <summary>Outcome of <see cref="ExchangePurposeService.RevokeByExchangePurposeAsync"/>.</summary>
public record BulkRevocationOutcome(
    bool Success,
    string? Error,
    IReadOnlyList<string> Revoked,
    IReadOnlyDictionary<string, string> Skipped,
    IReadOnlyList<string> CrlErrors);

/// <summary>
/// The exchange purposes (TEFCA XP codes) each subscriber organization is authorized for: recording and withdrawing
/// them, checking requested SANs against them, and revoking an organization's certificates for a withdrawn one.
/// Which SAN carries which exchange purpose is decided by <see cref="ExchangePurposeSan"/> alone.
/// </summary>
public class ExchangePurposeService(
    PortalDbContext db,
    CaApiClient ca,
    PortalAuditTrail audit,
    ILogger<ExchangePurposeService> logger)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>The organization's authorized exchange purposes, by code.</summary>
    public async Task<List<OrganizationExchangePurpose>> ListAsync(int organizationId, CancellationToken ct = default) =>
        await db.OrganizationExchangePurposes
            .Where(x => x.OrganizationId == organizationId)
            .OrderBy(x => x.Code)
            .ToListAsync(ct);

    /// <summary>The codes the organization is authorized for; empty when there is no organization.</summary>
    public async Task<IReadOnlySet<string>> AuthorizedCodesAsync(int? organizationId, CancellationToken ct = default)
    {
        if (organizationId is null) return new HashSet<string>(StringComparer.Ordinal);
        var codes = await db.OrganizationExchangePurposes
            .Where(x => x.OrganizationId == organizationId)
            .Select(x => x.Code)
            .ToListAsync(ct);
        return codes.ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>Exchange purposes carried by <paramref name="sans"/> that are not in <paramref name="authorized"/>, sorted.</summary>
    public static IReadOnlyList<string> Unauthorized(IEnumerable<ApiSanEntry> sans, IReadOnlySet<string> authorized) =>
        ExchangePurposeSan.ExtractAll(sans).Where(xp => !authorized.Contains(xp)).Order(StringComparer.Ordinal).ToList();

    /// <summary>Exchange purposes the request's SANs carry that its organization is not authorized for.</summary>
    public async Task<IReadOnlyList<string>> UnauthorizedForRequestAsync(CertificateRequest request, CancellationToken ct = default)
    {
        var sans = JsonSerializer.Deserialize<List<ApiSanEntry>>(request.RequestedSansJson ?? "[]", Json) ?? [];
        return Unauthorized(sans, await AuthorizedCodesAsync(request.OrganizationId, ct));
    }

    /// <summary>Records that the organization is authorized for <paramref name="code"/>. Re-authorizing is a no-op.</summary>
    public async Task<OrganizationExchangePurpose> AuthorizeAsync(
        int organizationId, string code, string approvedBy, CancellationToken ct = default)
    {
        var normalized = ExchangePurposeSan.Normalize(code)
            ?? throw new ArgumentException($"'{code}' is not an exchange purpose code (e.g. T-TRTMNT).", nameof(code));
        var org = await db.Organizations.FindAsync([organizationId], ct)
            ?? throw new InvalidOperationException($"Organization {organizationId} not found.");

        var existing = await db.OrganizationExchangePurposes
            .FirstOrDefaultAsync(x => x.OrganizationId == organizationId && x.Code == normalized, ct);
        if (existing is not null) return existing;

        var row = new OrganizationExchangePurpose
        {
            OrganizationId = organizationId,
            Code = normalized,
            ApprovedBy = approvedBy,
            ApprovedAt = DateTime.UtcNow,
        };
        db.OrganizationExchangePurposes.Add(row);
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync(approvedBy, PortalAuditActions.ExchangePurposeAuthorized, null,
            $"{org.Name} (organization {org.Id}) authorized for {normalized}.");
        return row;
    }

    /// <summary>Withdraws the organization's authorization for <paramref name="code"/>; false if it had none.</summary>
    public async Task<bool> WithdrawAsync(int organizationId, string code, string actor, CancellationToken ct = default)
    {
        var normalized = ExchangePurposeSan.Normalize(code);
        if (normalized is null) return false;

        var row = await db.OrganizationExchangePurposes
            .Include(x => x.Organization)
            .FirstOrDefaultAsync(x => x.OrganizationId == organizationId && x.Code == normalized, ct);
        if (row is null) return false;

        db.OrganizationExchangePurposes.Remove(row);
        await db.SaveChangesAsync(ct);
        await audit.RecordAsync(actor, PortalAuditActions.ExchangePurposeWithdrawn, null,
            $"{row.Organization.Name} (organization {organizationId}) no longer authorized for {normalized}; " +
            $"authorized by {row.ApprovedBy} at {row.ApprovedAt:O}.");
        return true;
    }

    /// <summary>The organization's issued (not yet revoked) certificates whose SANs carry <paramref name="code"/>.</summary>
    public async Task<List<CertificateRequest>> FindIssuedCarryingAsync(
        int organizationId, string code, CancellationToken ct = default)
    {
        var normalized = ExchangePurposeSan.Normalize(code);
        if (normalized is null) return [];

        var issued = await db.CertificateRequests
            .Where(r => r.OrganizationId == organizationId && r.Status == RequestStatus.Issued && r.SerialNumber != null)
            .OrderBy(r => r.Id)
            .ToListAsync(ct);
        return issued.Where(r => CarriedExchangePurposes(r).Contains(normalized)).ToList();
    }

    /// <summary>
    /// Revokes (reason <c>privilegeWithdrawn</c>) every issued certificate of the organization whose SANs carry
    /// <paramref name="code"/>. The CA re-checks each certificate, records each revocation and publishes new CRLs;
    /// the portal marks the requests revoked and records the action in its own audit trail.
    /// </summary>
    public async Task<BulkRevocationOutcome> RevokeByExchangePurposeAsync(
        int organizationId, string code, string actor, CancellationToken ct = default)
    {
        var normalized = ExchangePurposeSan.Normalize(code)
            ?? throw new ArgumentException($"'{code}' is not an exchange purpose code (e.g. T-TRTMNT).", nameof(code));
        var org = await db.Organizations.FindAsync([organizationId], ct)
            ?? throw new InvalidOperationException($"Organization {organizationId} not found.");
        var subscriber = $"{org.Name} (organization {org.Id})";

        var requests = await FindIssuedCarryingAsync(organizationId, normalized, ct);
        if (requests.Count == 0)
        {
            await audit.RecordAsync(actor, PortalAuditActions.CertificatesRevokedByExchangePurpose, null,
                $"No issued certificates of {subscriber} carry {normalized}; nothing revoked.");
            return new BulkRevocationOutcome(true, null, [], new Dictionary<string, string>(), []);
        }

        RevocationApiResult result;
        try
        {
            result = await ca.RevokeByExchangePurposeAsync(new RevocationApiRequest
            {
                SerialNumbers = requests.Select(r => r.SerialNumber!).ToList(),
                ExchangePurpose = normalized,
                SubscriberRef = subscriber,
                RequestedBy = actor,
            }, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            logger.LogError(ex, "CA revocation call failed for {Subscriber} / {Code}", subscriber, normalized);
            result = RevocationApiResult.Failure($"CA call failed: {ex.Message}");
        }

        if (!result.Success)
        {
            await audit.RecordAsync(actor, PortalAuditActions.CertificatesRevokedByExchangePurpose, null,
                $"Revoking certificates of {subscriber} carrying {normalized} failed: {result.Error}", succeeded: false);
            return new BulkRevocationOutcome(false, result.Error, [], new Dictionary<string, string>(), []);
        }

        var revoked = result.Revoked.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var request in requests.Where(r => revoked.Contains(r.SerialNumber!)))
        {
            request.Status = RequestStatus.Revoked;
            request.UpdatedAt = DateTime.UtcNow;
            request.Events.Add(new RequestEvent
            {
                Actor = actor,
                EventType = "Revoked",
                Detail = $"privilegeWithdrawn: exchange purpose {normalized} withdrawn for {subscriber}.",
            });
        }
        await db.SaveChangesAsync(ct);

        await audit.RecordAsync(actor, PortalAuditActions.CertificatesRevokedByExchangePurpose, null,
            $"Revoked {result.Revoked.Count} certificate(s) of {subscriber} carrying {normalized}" +
            (result.Revoked.Count > 0 ? $": {string.Join(", ", result.Revoked)}" : "") + "." +
            (result.Skipped.Count > 0
                ? $" Skipped: {string.Join("; ", result.Skipped.Select(s => $"{s.Key} ({s.Value})"))}."
                : "") +
            (result.CrlErrors.Count > 0 ? $" CRL problems: {string.Join("; ", result.CrlErrors)}." : ""));

        return new BulkRevocationOutcome(true, null, result.Revoked, result.Skipped, result.CrlErrors);
    }

    /// <summary>Exchange purposes the issued certificate's SANs carry, or the requested SANs' when it can't be read.</summary>
    private static IReadOnlySet<string> CarriedExchangePurposes(CertificateRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.CertificatePem))
        {
            try
            {
                using var cert = X509Certificate2.CreateFromPem(request.CertificatePem);
                return ExchangePurposeSan.ExtractAll(cert);
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException)
            {
                // Fall back to what was requested.
            }
        }

        var sans = JsonSerializer.Deserialize<List<ApiSanEntry>>(request.RequestedSansJson ?? "[]", Json) ?? [];
        return ExchangePurposeSan.ExtractAll(sans);
    }
}
