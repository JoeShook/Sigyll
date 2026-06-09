#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Portal.Data.Entities;

/// <summary>
/// A certificate request flowing through the portal: submission → classification policy →
/// (domain validation + auto-issue) or (RA approval) → issuance via the CA core. The portal
/// stores the CSR and the issued cert/chain PEM, but never any private-key material.
/// </summary>
public class CertificateRequest
{
    public int Id { get; set; }

    /// <summary>Identity user id of the requester.</summary>
    public string RequesterId { get; set; } = string.Empty;
    public int? OrganizationId { get; set; }

    public string TrustDomainName { get; set; } = string.Empty;
    public string TemplateName { get; set; } = string.Empty;

    /// <summary>Subject DN parsed from the CSR (for display/audit).</summary>
    public string SubjectDn { get; set; } = string.Empty;

    /// <summary>Requested SANs as JSON (list of {type,value}).</summary>
    public string? RequestedSansJson { get; set; }

    /// <summary>The caller-supplied PKCS#10 CSR, PEM-encoded.</summary>
    public string CsrPem { get; set; } = string.Empty;

    public RequestStatus Status { get; set; } = RequestStatus.Draft;

    // Classification policy decision
    public PolicyDecisionKind? PolicyDecision { get; set; }
    public string? PolicyReason { get; set; }

    /// <summary>Validation method chosen for auto-issue (e.g. "http-01").</summary>
    public string? ValidationMethod { get; set; }

    // RA decision (when routed to a human)
    public string? RaApproverId { get; set; }
    public string? RaReason { get; set; }
    public DateTime? RaDecisionAt { get; set; }

    /// <summary>Reference recorded on the issued request that authorized non-DV identifiers
    /// (sent to the CA as RaApprovalRef). Set when an RA approves.</summary>
    public string? RaApprovalRef { get; set; }

    // Issuance result (from the CA core; no private key)
    public string? SerialNumber { get; set; }
    public string? Thumbprint { get; set; }
    public string? CertificatePem { get; set; }
    public string? ChainPem { get; set; }
    public string? FailureReason { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? SubmittedAt { get; set; }
    public DateTime? IssuedAt { get; set; }

    public ICollection<RequestEvent> Events { get; set; } = new List<RequestEvent>();
    public ICollection<DomainValidationChallenge> Challenges { get; set; } = new List<DomainValidationChallenge>();
}

/// <summary>Lifecycle state of a certificate request.</summary>
public enum RequestStatus
{
    Draft = 0,
    Submitted = 1,
    PolicyEvaluated = 2,
    PendingValidation = 3,
    Validated = 4,
    PendingRaApproval = 5,
    Approved = 6,
    Rejected = 7,
    Issuing = 8,
    Issued = 9,
    Failed = 10,
    Closed = 11,
}

/// <summary>Outcome of the classification policy evaluation.</summary>
public enum PolicyDecisionKind
{
    /// <summary>Eligible for automated issuance after domain validation.</summary>
    AutoIssue = 0,

    /// <summary>Must be reviewed and approved by a human Registration Authority.</summary>
    RequiresRaApproval = 1,

    /// <summary>Not permitted (e.g. requester not authorized for the trust domain/template).</summary>
    Denied = 2,
}
