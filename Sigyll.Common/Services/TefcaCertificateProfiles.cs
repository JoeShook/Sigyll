#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Sigyll.Common.Data.Entities;

namespace Sigyll.Common.Services;

/// <summary>
/// Preset certificate profiles for TEFCA FHIR (RCE UDAP) certificates, following DirectTrust Certificate
/// Profiles v2.1, Worksheet 4-4 (TEFCA RCE (UDAP)) and its Appendix validation profile.
/// Production and validation leaves differ in the subject OU and in the certificate policies; validation
/// certificates chain to a different root and intermediate than production ones, so issue them from a
/// separate trust domain.
/// </summary>
public static class TefcaCertificateProfiles
{
    public const string IntermediateName = "TEFCA Intermediate CA";
    public const string ClientName = "TEFCA FHIR Client";
    public const string ServerName = "TEFCA FHIR Server";
    public const string ValidationClientName = "TEFCA FHIR Client (Validation)";
    public const string ValidationServerName = "TEFCA FHIR Server (Validation)";

    /// <summary>Subject OU of production TEFCA FHIR certificates.</summary>
    public const string ProductionOu = "RCE-FHIR";

    /// <summary>Subject OU of validation (test) TEFCA FHIR certificates.</summary>
    public const string ValidationOu = "RCE-FHIR-TEST";

    /// <summary>DirectTrust Certificate Policy.</summary>
    public const string DirectTrustCpOid = "1.3.6.1.4.1.41179.0.2";

    /// <summary>DirectTrust identity assurance level IAL2.</summary>
    public const string Ial2Oid = "1.3.6.1.4.1.41179.1.5";

    /// <summary>DirectTrust Device certificate.</summary>
    public const string DeviceOid = "1.3.6.1.4.1.41179.3.1";

    /// <summary>
    /// The certificate policies of production client and server leaves. A healthcare category policy is
    /// added on top when the certificate asserts an organization; clone the preset to add it.
    /// </summary>
    public const string ProductionPolicyOids = DirectTrustCpOid + ";" + Ial2Oid + ";" + DeviceOid;

    /// <summary>Leaf validity: three years is the maximum.</summary>
    public const int LeafValidityDays = 1095;

    public static IEnumerable<CertificateProfile> All()
    {
        yield return Intermediate();
        yield return Leaf(ClientName, CertificateType.EndEntityClient, ProductionOu, ProductionPolicyOids,
            "TEFCA FHIR (RCE UDAP) client certificate, production. CN must be one of the UDAP URI SANs " +
            "(at most 64 characters). Add a healthcare category policy when the certificate asserts an organization.");
        yield return Leaf(ServerName, CertificateType.EndEntityServer, ProductionOu, ProductionPolicyOids,
            "TEFCA FHIR (RCE UDAP) server certificate, production. CN must be one of the UDAP URI SANs " +
            "(at most 64 characters), such as the FHIR base URL. Add a healthcare category policy when the " +
            "certificate asserts an organization.");
        yield return Leaf(ValidationClientName, CertificateType.EndEntityClient, ValidationOu, policyOids: null,
            "TEFCA FHIR (RCE UDAP) client certificate for validation. Issue from a validation trust domain " +
            "(its own root and intermediate). Certificate policies may be added but are not required.");
        yield return Leaf(ValidationServerName, CertificateType.EndEntityServer, ValidationOu, policyOids: null,
            "TEFCA FHIR (RCE UDAP) server certificate for validation. Issue from a validation trust domain " +
            "(its own root and intermediate). Certificate policies may be added but are not required.");
    }

    private static CertificateProfile Intermediate() => new()
    {
        Name = IntermediateName,
        Description = "TEFCA FHIR intermediate CA, issued by a root; issues TEFCA FHIR client and server " +
                      "certificates. Path length 0. CRL distribution point and AIA must be http URLs, so " +
                      "the trust domain's base URL (or the URL templates) must use http.",
        CertificateType = CertificateType.IntermediateCa,
        KeyAlgorithm = "RSA",
        KeySize = 4096,
        ValidityDays = 1825,
        KeyUsageFlags = (int)(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign),
        IsKeyUsageCritical = true,
        IsBasicConstraintsCa = true,
        IsBasicConstraintsCritical = true,
        PathLengthConstraint = 0,
        HashAlgorithm = "SHA256",
        IncludeCdp = true,
        IncludeAia = true,
        SubjectAltNameTypes = null,
        IsPreset = true,
    };

    private static CertificateProfile Leaf(string name, CertificateType type, string ou, string? policyOids,
        string description) => new()
    {
        Name = name,
        Description = description,
        CertificateType = type,
        KeyAlgorithm = "RSA",
        KeySize = 2048,
        ValidityDays = LeafValidityDays,
        KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
        IsKeyUsageCritical = true,
        ExtendedKeyUsageOids = null,
        IsBasicConstraintsCa = false,
        IsBasicConstraintsCritical = true,
        CertificatePolicyOids = policyOids,
        HashAlgorithm = "SHA256",
        SubjectTemplate = $"CN={{UDAP URI}}, OU={ou}, O={{Organization}}, ST={{State}}, C=US",
        IncludeCdp = true,
        IncludeAia = true,
        // URIs only. An NPI otherName is optional, so NPI is not listed (listed SAN types are required).
        SubjectAltNameTypes = "URI",
        IsPreset = true,
        RequiresRaApproval = true,
    };
}
