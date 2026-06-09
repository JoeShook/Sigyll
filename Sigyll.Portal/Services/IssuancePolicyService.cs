#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Contracts;
using Sigyll.Portal.Data.Entities;

namespace Sigyll.Portal.Services;

/// <summary>
/// Decides how a certificate request is fulfilled: automated issuance after domain validation
/// (Let's-Encrypt-style, for TLS server certs) versus routing to a human Registration Authority.
/// Pure and deterministic so it is unit-testable. The CA's template flags (carried in the catalog)
/// are the source of truth for policy.
/// </summary>
public class IssuancePolicyService
{
    /// <summary>
    /// Evaluates policy for a request. <paramref name="requesterAuthorizedForTrustDomain"/> reflects
    /// org membership; it never blocks domain-validated auto-issue (TLS is open like ACME), but a
    /// lack of authorization keeps non-auto-issue requests on the human RA path.
    /// </summary>
    public PolicyDecision Evaluate(
        CatalogTemplate? template,
        IReadOnlyList<ApiSanEntry> sans,
        bool requesterAuthorizedForTrustDomain)
    {
        if (template is null)
            return new PolicyDecision(PolicyDecisionKind.Denied, "Unknown or unavailable template.");

        // Templates explicitly flagged for RA always require human review (e.g. UDAP client certs).
        if (template.RequiresRaApproval)
            return new PolicyDecision(PolicyDecisionKind.RequiresRaApproval,
                $"Template '{template.Name}' requires Registration Authority approval.");

        // TLS server certs with DNS SANs can auto-issue after domain validation — regardless of
        // org membership (domain control is the proof, as with ACME).
        bool allDns = sans.Count > 0 &&
            sans.All(s => string.Equals(s.Type, "Dns", StringComparison.OrdinalIgnoreCase));
        bool isServer = string.Equals(template.CertificateType, "EndEntityServer", StringComparison.OrdinalIgnoreCase);

        if (template.AllowAutoIssue && isServer && allDns)
            return new PolicyDecision(PolicyDecisionKind.AutoIssue,
                "TLS server certificate with DNS SANs — eligible for domain-validated auto-issue.",
                ValidationMethod: "http-01");

        // Everything else is reviewed by a human. Note membership in the reason for the RA's context.
        var membershipNote = requesterAuthorizedForTrustDomain
            ? "requester is authorized for the trust domain"
            : "requester is not yet authorized for the trust domain";
        return new PolicyDecision(PolicyDecisionKind.RequiresRaApproval,
            $"Manual RA review required ({membershipNote}).");
    }
}

/// <summary>Result of a policy evaluation.</summary>
public record PolicyDecision(PolicyDecisionKind Kind, string Reason, string? ValidationMethod = null);
