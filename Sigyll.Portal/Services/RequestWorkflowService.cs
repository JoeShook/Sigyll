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
    ILogger<RequestWorkflowService> logger)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Submits a new request, runs policy, and routes it to validation or the RA queue.</summary>
    public async Task<CertificateRequest> SubmitAsync(
        string requesterId,
        int? organizationId,
        string trustDomainName,
        string templateName,
        string subjectDn,
        List<ApiSanEntry> sans,
        string csrPem,
        CancellationToken ct = default)
    {
        var request = new CertificateRequest
        {
            RequesterId = requesterId,
            OrganizationId = organizationId,
            TrustDomainName = trustDomainName,
            TemplateName = templateName,
            SubjectDn = subjectDn,
            RequestedSansJson = JsonSerializer.Serialize(sans, Json),
            CsrPem = csrPem,
            Status = RequestStatus.Submitted,
            SubmittedAt = DateTime.UtcNow,
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(ct);
        AddEvent(request, requesterId, "Submitted", $"{templateName} under {trustDomainName}");

        // Classify.
        var template = await catalog.FindTemplateAsync(templateName, ct);
        var authorized = await IsRequesterAuthorizedAsync(requesterId, trustDomainName, ct);
        var decision = policy.Evaluate(template, sans, authorized);
        request.PolicyDecision = decision.Kind;
        request.PolicyReason = decision.Reason;
        request.ValidationMethod = decision.ValidationMethod;
        request.Status = RequestStatus.PolicyEvaluated;
        AddEvent(request, "system", "PolicyEvaluated", $"{decision.Kind}: {decision.Reason}");

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
            TemplateName = request.TemplateName,
            TrustDomainName = request.TrustDomainName,
            RequesterRef = request.RequesterId,
            RaApprovalRef = raApprovalRef,
            ValidatedIdentifiers = validatedIdentifiers,
            RequestedSans = sans,
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

    private async Task<CertificateRequest> LoadAsync(int requestId, CancellationToken ct) =>
        await db.CertificateRequests
            .Include(r => r.Challenges)
            .FirstOrDefaultAsync(r => r.Id == requestId, ct)
        ?? throw new InvalidOperationException($"Request {requestId} not found.");

    private static void AddEvent(CertificateRequest request, string actor, string type, string? detail) =>
        request.Events.Add(new RequestEvent { Actor = actor, EventType = type, Detail = detail });
}
