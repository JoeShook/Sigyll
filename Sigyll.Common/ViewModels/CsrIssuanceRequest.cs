#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.ViewModels;

/// <summary>
/// Request DTO for issuing an end-entity certificate from a caller-supplied PKCS#10 CSR.
/// The CA uses the public key and subject from the CSR and never sees the requester's private key.
/// Consumed by the internal RA issuance API (the portal) and by tests.
/// </summary>
public class CsrIssuanceRequest
{
    /// <summary>The issuing CA. Required — CSR issuance always produces a CA-signed end-entity cert.</summary>
    public int IssuingCaCertificateId { get; set; }

    /// <summary>Template (classification) that defines extensions, EKU/KU, and validity.</summary>
    public int TemplateId { get; set; }

    /// <summary>Trust domain the certificate belongs to.</summary>
    public int TrustDomainId { get; set; }

    /// <summary>The PKCS#10 certificate signing request, PEM-encoded.</summary>
    public string CsrPem { get; set; } = string.Empty;

    /// <summary>Friendly display name; defaults to the CSR subject CN when empty.</summary>
    public string CertificateName { get; set; } = string.Empty;

    /// <summary>Authoritative SAN set to place on the certificate (template/portal-driven).</summary>
    public List<SanEntry> SubjectAltNames { get; set; } = [];

    public List<string> CdpUrls { get; set; } = [];
    public List<string> AiaUrls { get; set; } = [];

    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>Override for the issuer's signing provider; null uses the configured provider.</summary>
    public string? SigningProviderOverride { get; set; }

    /// <summary>
    /// When this issuance is a renewal (re-key), the ID of the IssuedCertificate being
    /// replaced. The new certificate records the lineage link and Version = predecessor + 1.
    /// </summary>
    public int? RenewalOfCertificateId { get; set; }
}

/// <summary>
/// Result of CSR-based issuance. Carries the issued certificate and chain as PEM so the caller
/// (the RA portal) can return them without any private-key material.
/// </summary>
public class CsrIssuanceResult : CertificateIssuanceResult
{
    /// <summary>The issued end-entity certificate, PEM-encoded.</summary>
    public string? CertificatePem { get; set; }

    /// <summary>The issuing chain (issuer up to root), PEM-encoded, in order.</summary>
    public string? ChainPem { get; set; }

    public static new CsrIssuanceResult Failure(string error) =>
        new() { Success = false, Error = error };
}
