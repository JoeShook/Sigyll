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
/// Sanitized catalog the CA core publishes to the RA portal (<c>GET /api/ra/catalog</c>) so the
/// portal can offer trust domains and templates without holding any CA state. Contains no secrets,
/// key material, or internal storage hints — only what the request wizard and policy engine need.
/// </summary>
public class CatalogResponse
{
    public List<CatalogTrustDomain> TrustDomains { get; set; } = [];
    public List<CatalogTemplate> Templates { get; set; } = [];
}

/// <summary>A trust domain offered to requesters.</summary>
public class CatalogTrustDomain
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Enabled { get; set; }
}

/// <summary>
/// A certificate template ("classification") offered to requesters, with the policy flags the
/// portal's <c>IssuancePolicyService</c> uses to decide auto-issue vs. RA approval. The CA remains
/// the single source of truth for these flags.
/// </summary>
public class CatalogTemplate
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>One of: <c>RootCa</c>, <c>IntermediateCa</c>, <c>EndEntityClient</c>, <c>EndEntityServer</c>.</summary>
    public string CertificateType { get; set; } = string.Empty;

    /// <summary>Semicolon-delimited SAN type hints, e.g. "DNS" or "URI;DNS".</summary>
    public string? AllowedSanTypes { get; set; }

    /// <summary>When true, requests for this template may be auto-issued after domain validation.</summary>
    public bool AllowAutoIssue { get; set; }

    /// <summary>When true, requests for this template always require human RA approval.</summary>
    public bool RequiresRaApproval { get; set; }
}
