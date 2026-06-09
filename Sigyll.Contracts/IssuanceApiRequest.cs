#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Contracts;

/// <summary>
/// Wire contract sent by the RA portal to the CA core's internal issuance API
/// (<c>POST /api/ra/issue</c>). The portal never holds CA signing keys; it submits a CSR plus the
/// profile selection and proof of authorization (domain-validated identifiers and/or an RA approval
/// reference). The CA re-checks these before signing.
/// </summary>
public class IssuanceApiRequest
{
    /// <summary>The PKCS#10 certificate signing request, PEM-encoded. The CA uses the public key
    /// from this CSR and never sees the requester's private key.</summary>
    public string CsrPem { get; set; } = string.Empty;

    /// <summary>Name of the certificate template (the "classification") to apply, as published in
    /// the catalog. The CA resolves this to a <c>CertificateTemplate</c>.</summary>
    public string TemplateName { get; set; } = string.Empty;

    /// <summary>Name of the trust domain the certificate is issued under, as published in the catalog.</summary>
    public string TrustDomainName { get; set; } = string.Empty;

    /// <summary>Opaque portal reference for the requesting user/organization, recorded for audit.</summary>
    public string RequesterRef { get; set; } = string.Empty;

    /// <summary>Set by the portal when a human RA approved the request. Null for auto-issued
    /// (domain-validated) requests. Presence authorizes identifiers that were not domain-validated.</summary>
    public string? RaApprovalRef { get; set; }

    /// <summary>DNS identifiers the portal proved control of (http-01). The CA requires every DNS
    /// SAN in the CSR/request to appear here unless an <see cref="RaApprovalRef"/> is present.</summary>
    public List<string> ValidatedIdentifiers { get; set; } = [];

    /// <summary>Subject Alternative Names requested for the certificate.</summary>
    public List<ApiSanEntry> RequestedSans { get; set; } = [];
}

/// <summary>A single Subject Alternative Name entry on the wire.</summary>
public class ApiSanEntry
{
    /// <summary>One of: <c>Uri</c>, <c>Dns</c>, <c>Email</c>, <c>IpAddress</c>.</summary>
    public string Type { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}
