#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Data.Entities;

namespace Sigyll.Common.ViewModels;

/// <summary>Input for <c>ExternalCertificateRequestService.CreateAsync</c>.</summary>
public class CreateExternalCertificateRequest
{
    public int TrustDomainId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string SubjectDn { get; set; } = string.Empty;
    public List<SanEntry> SubjectAltNames { get; set; } = [];

    /// <summary>"RSA" or "ECDSA".</summary>
    public string KeyAlgorithm { get; set; } = "RSA";
    /// <summary>RSA bits (2048/3072/4096) or ECDSA curve size (256/384/521).</summary>
    public int KeySize { get; set; } = 2048;

    public CsrExtensionProfile Profile { get; set; } = CsrExtensionProfile.UdapClient;

    /// <summary>Optional: the certificate this request renews (lineage + source for FromModeledCertificate).</summary>
    public int? ModeledOnCertificateId { get; set; }
    public string? ModeledOnEntityType { get; set; }

    public string? ExternalCaName { get; set; }
    public string? Notes { get; set; }
}

/// <summary>
/// Input for <c>ExternalCertificateRequestService.UpdateAsync</c>: change a pending request's
/// details and regenerate its CSR — e.g. after the external CA rejected the first submission.
/// The stored key is reused unless <see cref="RegenerateKey"/> is set.
/// </summary>
public class UpdateExternalCertificateRequest
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string SubjectDn { get; set; } = string.Empty;
    public List<SanEntry> SubjectAltNames { get; set; } = [];
    public CsrExtensionProfile Profile { get; set; } = CsrExtensionProfile.UdapClient;
    public string? ExternalCaName { get; set; }
    public string? Notes { get; set; }

    /// <summary>Discard the stored key and generate a new one (with the algorithm/size below).</summary>
    public bool RegenerateKey { get; set; }
    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 2048;
}

public class ExternalCertificateRequestResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public int? RequestId { get; set; }
    public string? CsrPem { get; set; }
    public string? PublicKeyThumbprint { get; set; }

    public static ExternalCertificateRequestResult Failure(string error) => new() { Success = false, Error = error };
}

/// <summary>Outcome of matching a CA-returned certificate to a stored request and importing it.</summary>
public class FulfillExternalRequestResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>The certificate matched the key but its issuer is not in the trust domain; supply an issuing CA or chain.</summary>
    public bool NeedsCaSelection { get; set; }
    public string? IssuerName { get; set; }

    public int TrustDomainId { get; set; }
    public int? CertificateId { get; set; }
    public string? EntityType { get; set; }
    public string? Thumbprint { get; set; }
    public string? ImportedName { get; set; }
    public int ChainCertificatesImported { get; set; }

    public static FulfillExternalRequestResult Failure(string error) => new() { Success = false, Error = error };
}

/// <summary>Row model for the External CA Requests page.</summary>
public class ExternalCertificateRequestSummary
{
    public int Id { get; set; }
    public int TrustDomainId { get; set; }
    public string TrustDomainName { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string SubjectDn { get; set; } = string.Empty;
    public List<SanEntry> SubjectAltNames { get; set; } = [];
    public string KeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public string PublicKeyThumbprint { get; set; } = string.Empty;
    public CsrExtensionProfile Profile { get; set; }
    public ExternalRequestStatus Status { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public DateTime? FulfilledAt { get; set; }
    public string? ExternalCaName { get; set; }
    public string? Notes { get; set; }
    public int? ModeledOnCertificateId { get; set; }
    public string? ModeledOnEntityType { get; set; }
    public int? FulfilledCertificateId { get; set; }
    public string? FulfilledEntityType { get; set; }
    public string? FulfilledThumbprint { get; set; }
}

public class ExternalRequestExportResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>Text payload (CSR PEM, key PEM). Null for binary exports.</summary>
    public string? Content { get; set; }

    /// <summary>Binary payload (.p12). Null for text exports.</summary>
    public byte[]? Bytes { get; set; }

    public string FileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "text/plain";

    public static ExternalRequestExportResult Failure(string error) => new() { Success = false, Error = error };
}
