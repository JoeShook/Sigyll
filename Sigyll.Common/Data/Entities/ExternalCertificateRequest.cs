#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Data.Entities;

/// <summary>Requested-extension profile placed in an outbound CSR. The CA applies its own policy; this states intent.</summary>
public enum CsrExtensionProfile
{
    /// <summary>No requested extensions beyond SANs.</summary>
    None = 0,

    /// <summary>Key Usage digitalSignature (critical); EKU clientAuth. Typical UDAP client certificate.</summary>
    UdapClient = 1,

    /// <summary>Key Usage digitalSignature + keyEncipherment (critical); EKU serverAuth.</summary>
    TlsServer = 2,

    /// <summary>Key Usage digitalSignature + keyEncipherment (critical); EKU serverAuth + clientAuth.</summary>
    TlsServerAndClient = 3,

    /// <summary>Copy Key Usage, Extended Key Usage and Basic Constraints verbatim from the modeled-on certificate.</summary>
    FromModeledCertificate = 4
}

public enum ExternalRequestStatus
{
    /// <summary>CSR generated; waiting for the external CA to return a certificate.</summary>
    Pending = 0,

    /// <summary>The CA's certificate was matched to the stored key and imported into the trust domain.</summary>
    Fulfilled = 1,

    /// <summary>Abandoned by the operator; the key is retained until the row is deleted.</summary>
    Cancelled = 2
}

/// <summary>
/// A certificate signing request destined for an external CA, together with the private key
/// that signed it. Sigyll keeps both so the operator does not have to juggle .csr/.key files:
/// when the CA's certificate comes back it is matched to this key (by public key) and imported
/// as an operational certificate. Distinct from the Portal's inbound requests, which are CSRs
/// submitted TO Sigyll's own CAs.
/// </summary>
public class ExternalCertificateRequest
{
    public int Id { get; set; }

    /// <summary>Trust domain the resulting certificate will be imported into.</summary>
    public int TrustDomainId { get; set; }
    public TrustDomain TrustDomain { get; set; } = null!;

    public string Name { get; set; } = string.Empty;
    public string SubjectDn { get; set; } = string.Empty;

    /// <summary>JSON array of {Type, Value} SAN entries as placed in the CSR.</summary>
    public string? SubjectAltNamesJson { get; set; }

    /// <summary>PEM PKCS#10 as handed to the external CA.</summary>
    public string CsrPem { get; set; } = string.Empty;

    public string KeyAlgorithm { get; set; } = "RSA";
    public int KeySize { get; set; } = 2048;

    /// <summary>SHA-256 over the SubjectPublicKeyInfo, upper-case hex. Used to recognise the CA's certificate.</summary>
    public string PublicKeyThumbprint { get; set; } = string.Empty;

    /// <summary>PKCS#8 private key, PEM, encrypted with <see cref="KeyPassword"/> (same posture as PfxPassword on certificates).</summary>
    public string EncryptedPrivateKeyPem { get; set; } = string.Empty;
    public string KeyPassword { get; set; } = string.Empty;

    /// <summary>Free text: which CA this is going to, ticket numbers, etc.</summary>
    public string? ExternalCaName { get; set; }
    public string? Notes { get; set; }

    /// <summary>When the request renews an existing certificate: that certificate, for lineage.</summary>
    public int? ModeledOnCertificateId { get; set; }
    /// <summary>"CaCertificate" or "IssuedCertificate".</summary>
    public string? ModeledOnEntityType { get; set; }

    /// <summary>Requested-extension profile the CSR was built with; kept so the request can be edited and regenerated.</summary>
    public CsrExtensionProfile Profile { get; set; } = CsrExtensionProfile.UdapClient;

    public ExternalRequestStatus Status { get; set; } = ExternalRequestStatus.Pending;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Last time the CSR was regenerated after an edit; null when never edited.</summary>
    public DateTime? UpdatedAt { get; set; }
    public DateTime? FulfilledAt { get; set; }

    /// <summary>The imported certificate once fulfilled.</summary>
    public int? FulfilledCertificateId { get; set; }
    public string? FulfilledEntityType { get; set; }
    public string? FulfilledThumbprint { get; set; }
}
