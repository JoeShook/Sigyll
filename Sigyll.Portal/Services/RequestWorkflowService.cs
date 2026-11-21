#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sigyll.Contracts;
using Sigyll.Portal.Data;
using Sigyll.Portal.Data.Entities;

namespace Sigyll.Portal.Services;

/// <summary>
/// Orchestrates a certificate request end-to-end: submit → classification policy →
/// (http-01 domain validation + auto-issue) or (human RA approval) → issuance via the CA core.
/// Every transition is recorded as a <see cref="RequestEvent"/>. The CA signs; the portal never
/// holds key material.
/// </summary>
public class RequestWorkflowService(
    PortalDbContext db,
    CatalogService catalog,
    IssuancePolicyService policy,
    DomainValidationService dv,
    CaApiClient ca,
    ExchangePurposeService exchangePurposes,
    ILogger<RequestWorkflowService> logger)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Submits a new request, runs policy, and routes it to validation or the RA queue.</summary>
    public async Task<CertificateRequest> SubmitAsync(
        string requesterId,
        int? organizationId,
        string trustDomainName,
        string profileName,
        string subjectDn,
        List<ApiSanEntry> sans,
        string csrPem,
        CancellationToken ct = default)
    {
        // A requester in exactly one enabled organization requests for it: the subscriber whose exchange purpose
        // authorizations apply and whose certificates a bulk revocation finds.
        organizationId ??= await SoleOrganizationAsync(requesterId, ct);

        var request = new CertificateRequest
        {
            RequesterId = requesterId,
            OrganizationId = organizationId,
            TrustDomainName = trustDomainName,
            ProfileName = profileName,
            SubjectDn = subjectDn,
            RequestedSansJson = JsonSerializer.Serialize(sans, Json),
            CsrPem = csrPem,
            Status = RequestStatus.Submitted,
            SubmittedAt = DateTime.UtcNow,
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(ct);
        AddEvent(request, requesterId, "Submitted", $"{profileName} under {trustDomainName}");

        // Classify.
        var profile = await catalog.FindProfileAsync(profileName, ct);
        var authorized = await IsRequesterAuthorizedAsync(requesterId, trustDomainName, ct);
        var decision = policy.Evaluate(profile, sans, authorized);
        request.PolicyDecision = decision.Kind;
        request.PolicyReason = decision.Reason;
        request.ValidationMethod = decision.ValidationMethod;
        request.Status = RequestStatus.PolicyEvaluated;
        AddEvent(request, "system", "PolicyEvaluated", $"{decision.Kind}: {decision.Reason}");

        // Flag SANs carrying an exchange purpose the subscriber is not authorized for; RA approval is blocked
        // until it is (see ApproveAsync).
        var unauthorizedPurposes = ExchangePurposeService.Unauthorized(
            sans, await exchangePurposes.AuthorizedCodesAsync(organizationId, ct));
        if (unauthorizedPurposes.Count > 0)
        {
            var flag = $"Subscriber is not authorized for exchange purpose(s): {string.Join(", ", unauthorizedPurposes)}.";
            request.PolicyReason = $"{request.PolicyReason} {flag}";
            AddEvent(request, "system", "ExchangePurposeFlagged", flag);
        }

        switch (decision.Kind)
        {
            case PolicyDecisionKind.AutoIssue:
                foreach (var dns in sans.Where(s => string.Equals(s.Type, "Dns", StringComparison.OrdinalIgnoreCase)))
                    request.Challenges.Add(dv.CreateChallenge(dns.Value));
                request.Status = RequestStatus.PendingValidation;
                AddEvent(request, "system", "ValidationRequested",
                    $"http-01 for: {string.Join(", ", request.Challenges.Select(c => c.Identifier))}");
                break;

            case PolicyDecisionKind.RequiresRaApproval:
                request.Status = RequestStatus.PendingRaApproval;
                AddEvent(request, "system", "QueuedForRa", decision.Reason);
                break;

            case PolicyDecisionKind.Denied:
                request.Status = RequestStatus.Rejected;
                request.FailureReason = decision.Reason;
                AddEvent(request, "system", "Denied", decision.Reason);
                break;
        }

        request.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return request;
    }

    /// <summary>Verifies all http-01 challenges for an auto-issue request and, when all pass, issues.</summary>
    public async Task<CertificateRequest> VerifyAndIssueAsync(int requestId, string actor, CancellationToken ct = default)
    {
        var request = await LoadAsync(requestId, ct);
        if (request.Status is not (RequestStatus.PendingValidation or RequestStatus.Validated))
            return request;

        foreach (var challenge in request.Challenges.Where(c => c.Status != DomainValidationStatus.Valid))
            await dv.VerifyAsync(challenge, ct);
        await db.SaveChangesAsync(ct);

        if (request.Challenges.Any(c => c.Status != DomainValidationStatus.Valid))
        {
            AddEvent(request, actor, "ValidationPending", "One or more identifiers not yet validated.");
            await db.SaveChangesAsync(ct);
            return request;
        }

        request.Status = RequestStatus.Validated;
        AddEvent(request, actor, "Validated", "All identifiers validated via http-01.");
        var validated = request.Challenges.Select(c => c.Identifier).ToList();
        await IssueAsync(request, validated, raApprovalRef: null, actor, ct);
        return request;
    }

    /// <summary>RA approves a request and issues it (RA approval authorizes non-validated identifiers).</summary>
    public async Task<CertificateRequest> ApproveAsync(int requestId, string raUserId, string reason, CancellationToken ct = default)
    {
        var request = await LoadAsync(requestId, ct);
        if (request.Status != RequestStatus.PendingRaApproval)
            return request;

        // Blocked while any SAN carries an exchange purpose the subscriber is not authorized for. The request stays
        // in the queue so it can be approved once the authorization is recorded, or rejected.
        var unauthorizedPurposes = await exchangePurposes.UnauthorizedForRequestAsync(request, ct);
        if (unauthorizedPurposes.Count > 0)
        {
            AddEvent(request, $"ra:{raUserId}", "ApprovalBlocked",
                $"Subscriber is not authorized for exchange purpose(s): {string.Join(", ", unauthorizedPurposes)}.");
            request.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            return request;
        }

        request.RaApproverId = raUserId;
        request.RaReason = reason;
        request.RaDecisionAt = DateTime.UtcNow;
        request.RaApprovalRef = $"ra:{raUserId}:{DateTime.UtcNow:O}";
        request.Status = RequestStatus.Approved;
        AddEvent(request, $"ra:{raUserId}", "Approved", reason);

        var validated = request.Challenges
            .Where(c => c.Status == DomainValidationStatus.Valid)
            .Select(c => c.Identifier)
            .ToList();
        await IssueAsync(request, validated, request.RaApprovalRef, $"ra:{raUserId}", ct);
        return request;
    }

    /// <summary>RA rejects a request.</summary>
    public async Task<CertificateRequest> RejectAsync(int requestId, string raUserId, string reason, CancellationToken ct = default)
    {
        var request = await LoadAsync(requestId, ct);
        if (request.Status != RequestStatus.PendingRaApproval)
            return request;

        request.RaApproverId = raUserId;
        request.RaReason = reason;
        request.RaDecisionAt = DateTime.UtcNow;
        request.Status = RequestStatus.Rejected;
        request.FailureReason = reason;
        AddEvent(request, $"ra:{raUserId}", "Rejected", reason);
        request.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return request;
    }

    private async Task IssueAsync(
        CertificateRequest request, List<string> validatedIdentifiers, string? raApprovalRef, string actor, CancellationToken ct)
    {
        request.Status = RequestStatus.Issuing;
        AddEvent(request, actor, "Issuing", "Submitting CSR to the CA core.");
        await db.SaveChangesAsync(ct);

        var sans = JsonSerializer.Deserialize<List<ApiSanEntry>>(request.RequestedSansJson ?? "[]", Json) ?? [];
        var apiRequest = new IssuanceApiRequest
        {
            CsrPem = request.CsrPem,
            ProfileName = request.ProfileName,
            TrustDomainName = request.TrustDomainName,
            RequesterRef = request.RequesterId,
            RaApprovalRef = raApprovalRef,
            ValidatedIdentifiers = validatedIdentifiers,
            RequestedSans = sans,
            // The CA re-checks every exchange purpose a SAN carries against this list.
            AuthorizedExchangePurposes = (await exchangePurposes.AuthorizedCodesAsync(request.OrganizationId, ct))
                .Order(StringComparer.Ordinal).ToList(),
        };

        IssuanceApiResult result;
        try
        {
            result = await ca.IssueAsync(apiRequest, ct);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "CA issuance call failed for request {Id}", request.Id);
            result = IssuanceApiResult.Failure($"CA call failed: {ex.Message}");
        }

        if (result.Success)
        {
            request.Status = RequestStatus.Issued;
            request.SerialNumber = result.SerialNumber;
            request.Thumbprint = result.Thumbprint;
            request.CertificatePem = result.CertificatePem;
            request.ChainPem = result.ChainPem;
            request.IssuedAt = DateTime.UtcNow;
            AddEvent(request, actor, "Issued", $"Serial {result.SerialNumber}");
        }
        else
        {
            request.Status = RequestStatus.Failed;
            request.FailureReason = result.Error;
            AddEvent(request, actor, "Failed", result.Error ?? "Unknown error");
        }

        request.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    private async Task<bool> IsRequesterAuthorizedAsync(string requesterId, string trustDomainName, CancellationToken ct)
    {
        var orgIds = await db.OrganizationMemberships
            .Where(m => m.UserId == requesterId)
            .Select(m => m.OrganizationId)
            .ToListAsync(ct);
        if (orgIds.Count == 0) return false;

        var authorized = await db.Organizations
            .Where(o => orgIds.Contains(o.Id) && o.Enabled && o.AuthorizedTrustDomains != null)
            .Select(o => o.AuthorizedTrustDomains!)
            .ToListAsync(ct);

        return authorized.Any(list => list
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(td => string.Equals(td, trustDomainName, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>The requester's organization when they belong to exactly one enabled organization; otherwise null.</summary>
    private async Task<int?> SoleOrganizationAsync(string requesterId, CancellationToken ct)
    {
        var orgIds = await db.OrganizationMemberships
            .Where(m => m.UserId == requesterId && m.Organization.Enabled)
            .Select(m => m.OrganizationId)
            .Distinct()
            .Take(2)
            .ToListAsync(ct);
        return orgIds.Count == 1 ? orgIds[0] : null;
    }

    private async Task<CertificateRequest> LoadAsync(int requestId, CancellationToken ct) =>
        await db.CertificateRequests
            .Include(r => r.Challenges)
            .FirstOrDefaultAsync(r => r.Id == requestId, ct)
        ?? throw new InvalidOperationException($"Request {requestId} not found.");

    private static void AddEvent(CertificateRequest request, string actor, string type, string? detail) =>
        request.Events.Add(new RequestEvent { Actor = actor, EventType = type, Detail = detail });
}
