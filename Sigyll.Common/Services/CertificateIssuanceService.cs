#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services.Audit;
using Sigyll.Common.Services.Publishing;
using Sigyll.Common.Services.Pqc;
using Sigyll.Common.Services.Signing;
using Sigyll.Common.Validators;
using Sigyll.Common.ViewModels;

namespace Sigyll.Common.Services;

/// <summary>
/// Certificate generation engine. Creates Root CAs, Intermediate CAs, and end-entity
/// certificates using .NET's CertificateRequest API with extension helpers extracted
/// from Udap.PKI.Generator. Designed for consumption by UI, CLI, and API hosts.
/// Supports local (PFX) and remote (Vault Transit) signing via ISigningProvider.
/// </summary>
public class CertificateIssuanceService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IOperatorContext _operator;
    private readonly ILogger<CertificateIssuanceService> _logger;
    private readonly ISigningProvider _signingProvider;
    private readonly IssuanceValidator _validator;
    private readonly AuditTrail _audit;

    public CertificateIssuanceService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        IOperatorContext operatorContext,
        ILogger<CertificateIssuanceService> logger,
        ISigningProvider? signingProvider = null,
        IssuanceValidator? validator = null,
        AuditTrail? audit = null,
        PublishingPathPolicy? publishingPaths = null)
    {
        _dbFactory = dbFactory;
        _operator = operatorContext;
        _logger = logger;
        _publishingPaths = publishingPaths ?? PublishingPathPolicy.Unrestricted;
        _signingProvider = signingProvider ?? new LocalSigningProvider();
        _validator = validator ?? new IssuanceValidator();
        _audit = audit ?? new AuditTrail(dbFactory, operatorContext);
    }

    private readonly PublishingPathPolicy _publishingPaths;

    public IssuanceValidator Validator => _validator;

    /// <summary>
    /// Whether the active signing provider is remote (keys don't leave the provider).
    /// </summary>
    public bool IsRemoteProvider => _signingProvider.ProviderName != "local";

    /// <summary>
    /// Issues a certificate based on the given request and profile.
    /// For Root CAs, IssuingCaCertificateId should be null (self-signed).
    /// For Intermediate CAs and end-entity certs, it must reference a CA with a private key.
    /// </summary>
    public async Task<CertificateIssuanceResult> IssueCertificateAsync(CertificateIssuanceRequest request)
    {
        var identity = await _operator.DemandAsync(Permission.Operate);
        var result = await IssueAsync(request);
        await RecordIssuanceAsync(identity, result.Success, result.EntityType, result.EntityId, result.SerialNumber,
            request.IssuingCaCertificateId is int issuer ? $"Issued by CA #{issuer}" : "Self-signed", request.SubjectDn,
            result.Error);
        return result;
    }

    private async Task RecordIssuanceAsync(OperatorIdentity identity, bool success, string? entityType, int? entityId,
        string? serialNumber, string how, string? requestedSubject, string? error)
    {
        if (success && entityType != null && entityId is int id)
            await _audit.RecordAsync(identity, AuditActions.CertificateIssued, entityType, id, $"{how}; serial {serialNumber}.");
        else
            await _audit.RecordAsync(identity, AuditActions.CertificateIssued,
                detail: $"{how}; subject {requestedSubject}. Failed: {error}", succeeded: false);
    }

    private async Task<CertificateIssuanceResult> IssueAsync(CertificateIssuanceRequest request)
    {

        await using var db = await _dbFactory.CreateDbContextAsync();

        // Load profile
        var profile = await db.CertificateProfiles.FindAsync(request.ProfileId);
        if (profile == null)
            return CertificateIssuanceResult.Failure("Profile not found.");

        // Validate trustDomain exists
        var trustDomain = await db.TrustDomains.FindAsync(request.TrustDomainId);
        if (trustDomain == null)
            return CertificateIssuanceResult.Failure("Trust domain not found.");

        if (string.IsNullOrWhiteSpace(request.SubjectDn))
            return CertificateIssuanceResult.Failure("Subject DN is required.");

        // Validate AIA URLs and SAN URIs up front — they must be absolute URIs
        var badAia = request.AiaUrls.FirstOrDefault(u => !Uri.TryCreate(u, UriKind.Absolute, out _));
        if (badAia != null)
            return CertificateIssuanceResult.Failure($"AIA URL is not a valid absolute URI: '{badAia}'. Use http:// or https://.");

        var badSanUri = request.SubjectAltNames
            .FirstOrDefault(s => s.Type == SanType.Uri && !Uri.TryCreate(s.Value, UriKind.Absolute, out _));
        if (badSanUri != null)
            return CertificateIssuanceResult.Failure($"SAN URI is not a valid absolute URI: '{badSanUri.Value}'. Use http:// or https:// (or a custom scheme like spiffe://).");

        var badSanValue = _validator.ValidateSanValues(request.SubjectAltNames);
        if (badSanValue != null)
            return CertificateIssuanceResult.Failure(badSanValue);

        // SAN types declared on the profile are mandatory, not hints
        var missingSanError = _validator.ValidateRequiredSanTypes(profile, request.SubjectAltNames);
        if (missingSanError != null)
            return CertificateIssuanceResult.Failure(missingSanError);

        // Renewal lineage: the predecessor determines the new certificate's version
        var (renewalVersion, renewalOfId, lineageError) = await ResolveRenewalLineageAsync(
            db, request.RenewalOfCertificateId,
            isCaLineage: profile.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa);
        if (lineageError != null)
            return CertificateIssuanceResult.Failure(lineageError);

        // Determine effective signing mode for this request
        bool useRemoteSigning = request.SigningProviderOverride != null
            ? request.SigningProviderOverride != "local"
            : IsRemoteProvider;

        if (PqcAlgorithms.IsPqc(profile.KeyAlgorithm))
        {
            if (PqcAlgorithms.IsKem(profile.KeyAlgorithm, profile.KeySize)
                && profile.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa)
            {
                return CertificateIssuanceResult.Failure(
                    "ML-KEM encapsulates keys; it cannot sign a certificate and cannot be a CA. Use ML-DSA, SLH-DSA, or composite ML-DSA for CA keys.");
            }

            var unsupported = PqcAlgorithms.UnsupportedReason(profile.KeyAlgorithm, profile.KeySize);
            if (unsupported != null)
                return CertificateIssuanceResult.Failure(unsupported);
        }

        // PFX password is only required for local signing
        if (!useRemoteSigning && string.IsNullOrWhiteSpace(request.PfxPassword))
            return CertificateIssuanceResult.Failure("PFX password is required.");

        // Determine if self-signed (root CA)
        bool isSelfSigned = request.IssuingCaCertificateId == null;

        if (isSelfSigned && profile.CertificateType != CertificateType.RootCa)
            return CertificateIssuanceResult.Failure("Only Root CA profiles can be used for self-signed certificates.");

        if (!isSelfSigned && profile.CertificateType == CertificateType.RootCa)
            return CertificateIssuanceResult.Failure("Root CA profile cannot be used with an issuing CA — root CAs are self-signed.");

        // Load issuing CA if not self-signed
        X509Certificate2? issuingCert = null;
        CaCertificate? issuingCaEntity = null;
        SigningKeyReference? issuerKeyRef = null;

        if (!isSelfSigned)
        {
            issuingCaEntity = await db.CaCertificates.FindAsync(request.IssuingCaCertificateId);
            if (issuingCaEntity == null)
                return CertificateIssuanceResult.Failure("Issuing CA not found.");

            // Check if the issuing CA uses a remote signing provider
            if (issuingCaEntity.StoreProviderHint?.StartsWith("vault-transit:") == true)
            {
                var vaultKeyName = issuingCaEntity.StoreProviderHint["vault-transit:".Length..];
                issuerKeyRef = new SigningKeyReference(
                    "vault-transit", vaultKeyName, issuingCaEntity.KeyAlgorithm, issuingCaEntity.KeySize);

                // Load the cert (public only) for issuer DN and extensions
                issuingCert = X509Certificate2.CreateFromPem(issuingCaEntity.X509CertificatePem);
            }
            else if (issuingCaEntity.StoreProviderHint?.StartsWith("gcp-kms:") == true)
            {
                var kmsKeyId = issuingCaEntity.StoreProviderHint["gcp-kms:".Length..];
                issuerKeyRef = new SigningKeyReference(
                    "gcp-kms", kmsKeyId, issuingCaEntity.KeyAlgorithm, issuingCaEntity.KeySize);

                issuingCert = X509Certificate2.CreateFromPem(issuingCaEntity.X509CertificatePem);
            }
            else
            {
                // Local signing — need the PFX with private key
                if (issuingCaEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(issuingCaEntity.PfxPassword))
                    return CertificateIssuanceResult.Failure("Issuing CA does not have a private key. Import the PFX first.");

                try
                {
                    issuingCert = X509CertificateLoader.LoadPkcs12(
                        issuingCaEntity.EncryptedPfxBytes,
                        issuingCaEntity.PfxPassword,
                        X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    return CertificateIssuanceResult.Failure($"Failed to load issuing CA private key: {ex.Message}");
                }
            }
        }

        // Route to appropriate signing path:
        // 1. Full remote: new cert key AND signing both in remote provider
        // 2. Hybrid: new cert key is LOCAL (PFX), but issuer signs via remote provider (Vault Transit)
        // 3. Full local: both key and signing are local (existing code below)
        if ((useRemoteSigning || issuerKeyRef != null)
            && (PqcAlgorithms.IsPqc(profile.KeyAlgorithm)
                || (issuingCaEntity != null && PqcAlgorithms.IsPqc(issuingCaEntity.KeyAlgorithm))))
        {
            return CertificateIssuanceResult.Failure(PqcAlgorithms.RemoteBlockedMessage);
        }

        if (useRemoteSigning)
        {
            return await IssueCertificateRemoteAsync(
                db, profile, request, isSelfSigned, issuingCert, issuingCaEntity, issuerKeyRef,
                renewalVersion, renewalOfId);
        }

        if (issuerKeyRef != null)
        {
            // Hybrid: local key + remote signing (e.g., end-entity with PFX, signed by Vault CA)
            return await IssueCertificateHybridAsync(
                db, profile, request, issuingCert!, issuingCaEntity!, issuerKeyRef,
                renewalVersion, renewalOfId);
        }

        X509Extension? relatedCertificate = null;
        if (request.RelatedCertificateId is int relatedId)
        {
            var related = await db.IssuedCertificates.FindAsync(relatedId);
            if (related == null)
                return CertificateIssuanceResult.Failure("Related certificate not found.");
            using var relatedCert = X509Certificate2.CreateFromPem(related.X509CertificatePem);
            relatedCertificate = CertificateExtensionHelpers.BuildRelatedCertificate(relatedCert.RawData);
        }

        try
        {
            // Generate key pair
            using var keyHolder = GenerateKeyPair(profile);

            // Build CertificateRequest
            var certRequest = CreateCertificateRequest(profile, request.SubjectDn, keyHolder);

            // Add extensions
            AddExtensions(certRequest, profile, request, issuingCert);
            if (relatedCertificate != null)
                certRequest.CertificateExtensions.Add(relatedCertificate);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(profile.ValidityDays);

            // Clamp notAfter to issuing CA's expiry — .NET won't issue past the issuer's NotAfter
            if (issuingCert != null && notAfter > issuingCert.NotAfter)
            {
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            }

            X509Certificate2 cert;
            IDisposable? signatureKey = null;
            try
            {
                if (isSelfSigned)
                {
                    cert = certRequest.CreateSelfSigned(notBefore, notAfter);
                }
                else
                {
                    var serialBytes = RandomNumberGenerator.GetBytes(16);
                    var (generator, ownedKey) = OpenSignatureGenerator(issuingCert!);
                    signatureKey = ownedKey;
                    using var signedCert = certRequest.Create(
                        issuingCert!.SubjectName,
                        generator,
                        notBefore,
                        notAfter,
                        serialBytes);

                    cert = AttachPrivateKey(signedCert, keyHolder);
                }
            }
            finally
            {
                signatureKey?.Dispose();
            }

            using (cert)
            {
                // Verify the new cert was actually signed by the issuing CA
                if (!isSelfSigned)
                {
                    var issuerError = VerifyIssuedBy(cert, issuingCert!);
                    if (issuerError != null)
                        return CertificateIssuanceResult.Failure(issuerError);
                }

                // Export
                var pfxBytes = ExportPfx(cert, keyHolder, request.PfxPassword);
                var pem = cert.ExportCertificatePem();

                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                var described = PqcAlgorithms.DescribeCertificate(cert);

                // Store in database
                bool isCaType = profile.CertificateType is CertificateType.RootCa
                    or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        TrustDomainId = request.TrustDomainId,
                        ParentId = isSelfSigned ? null : request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = cert.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = described.Algorithm,
                        KeySize = described.KeySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrls.Count > 0 ? string.Join(";", request.CdpUrls) : null,
                        AuthorityInfoAccessUri = request.AiaUrls.Count > 0 ? string.Join(";", request.AiaUrls) : null,
                        Version = renewalVersion,
                        RenewalOfId = renewalOfId,
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    await PublishCaCertAndCrlAsync(request.TrustDomainId, certName, cert.RawData);

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        ProfileId = request.ProfileId,
                        Name = certName,
                        Subject = cert.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = described.Algorithm,
                        KeySize = described.KeySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        Version = renewalVersion,
                        RenewalOfId = renewalOfId,
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert?.Dispose();
        }
    }

    /// <summary>
    /// Resolves renewal lineage for an issuance request: the new certificate's Version is the
    /// predecessor's + 1 and RenewalOfId links back to it. Returns an error when the
    /// referenced predecessor doesn't exist in the expected table.
    /// </summary>
    private static async Task<(int Version, int? RenewalOfId, string? Error)> ResolveRenewalLineageAsync(
        SigyllDbContext db, int? renewalOfCertificateId, bool isCaLineage)
    {
        if (renewalOfCertificateId is not int predecessorId)
            return (1, null, null);

        int? predecessorVersion = isCaLineage
            ? (await db.CaCertificates.FindAsync(predecessorId))?.Version
            : (await db.IssuedCertificates.FindAsync(predecessorId))?.Version;

        return predecessorVersion == null
            ? (1, null, "Renewal predecessor certificate not found.")
            : (predecessorVersion.Value + 1, predecessorId, null);
    }

    /// <summary>
    /// Issues a CA-signed end-entity certificate from a caller-supplied PKCS#10 CSR. The CSR's
    /// public key and subject are used as-is; no private key is generated or stored — the requester
    /// retains the private key. This is the issuance path used by the RA portal over the internal
    /// API, preserving the true RA/CA split (the portal never holds key material).
    /// </summary>
    public async Task<CsrIssuanceResult> IssueCertificateFromCsrAsync(CsrIssuanceRequest request)
    {
        var identity = await _operator.DemandAsync(Permission.Operate, Permission.IssueFromRa);
        var result = await IssueFromCsrAsync(request);
        await RecordIssuanceAsync(identity, result.Success, result.EntityType, result.EntityId, result.SerialNumber,
            $"Issued from a CSR by CA #{request.IssuingCaCertificateId}", request.CertificateName, result.Error);
        return result;
    }

    private async Task<CsrIssuanceResult> IssueFromCsrAsync(CsrIssuanceRequest request)
    {

        await using var db = await _dbFactory.CreateDbContextAsync();

        var profile = await db.CertificateProfiles.FindAsync(request.ProfileId);
        if (profile == null)
            return CsrIssuanceResult.Failure("Profile not found.");

        if (profile.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa)
            return CsrIssuanceResult.Failure("CSR issuance is only supported for end-entity profiles.");

        var trustDomain = await db.TrustDomains.FindAsync(request.TrustDomainId);
        if (trustDomain == null)
            return CsrIssuanceResult.Failure("Trust domain not found.");

        if (string.IsNullOrWhiteSpace(request.CsrPem))
            return CsrIssuanceResult.Failure("CSR is required.");

        // Parse the CSR. SHA-256/384/512 cover RSA and ECDSA. ML-DSA, SLH-DSA and composite
        // ML-DSA ignore the hash and verify the pure signature (empty context).
        CertificateRequest csr;
        try
        {
            csr = LoadSigningRequest(request.CsrPem);
        }
        catch (Exception ex)
        {
            return CsrIssuanceResult.Failure($"Failed to parse CSR: {ex.Message}");
        }

        var badSanUri = request.SubjectAltNames
            .FirstOrDefault(s => s.Type == SanType.Uri && !Uri.TryCreate(s.Value, UriKind.Absolute, out _));
        if (badSanUri != null)
            return CsrIssuanceResult.Failure($"SAN URI is not a valid absolute URI: '{badSanUri.Value}'.");

        var badSanValue = _validator.ValidateSanValues(request.SubjectAltNames);
        if (badSanValue != null)
            return CsrIssuanceResult.Failure(badSanValue);

        // SAN types declared on the profile are mandatory, not hints
        var missingSanError = _validator.ValidateRequiredSanTypes(profile, request.SubjectAltNames);
        if (missingSanError != null)
            return CsrIssuanceResult.Failure(missingSanError);

        // Renewal lineage: the predecessor determines the new certificate's version
        var (renewalVersion, renewalOfId, lineageError) = await ResolveRenewalLineageAsync(
            db, request.RenewalOfCertificateId, isCaLineage: false);
        if (lineageError != null)
            return CsrIssuanceResult.Failure(lineageError);

        var issuingCaEntity = await db.CaCertificates.FindAsync(request.IssuingCaCertificateId);
        if (issuingCaEntity == null)
            return CsrIssuanceResult.Failure("Issuing CA not found.");

        X509Certificate2? issuingCert = null;
        SigningKeyReference? issuerKeyRef = null;
        try
        {
            // Resolve the issuer's signing material (local PFX vs remote key reference).
            if (issuingCaEntity.StoreProviderHint?.StartsWith("vault-transit:") == true)
            {
                var vaultKeyName = issuingCaEntity.StoreProviderHint["vault-transit:".Length..];
                issuerKeyRef = new SigningKeyReference(
                    "vault-transit", vaultKeyName, issuingCaEntity.KeyAlgorithm, issuingCaEntity.KeySize);
                issuingCert = X509Certificate2.CreateFromPem(issuingCaEntity.X509CertificatePem);
            }
            else if (issuingCaEntity.StoreProviderHint?.StartsWith("gcp-kms:") == true)
            {
                var kmsKeyId = issuingCaEntity.StoreProviderHint["gcp-kms:".Length..];
                issuerKeyRef = new SigningKeyReference(
                    "gcp-kms", kmsKeyId, issuingCaEntity.KeyAlgorithm, issuingCaEntity.KeySize);
                issuingCert = X509Certificate2.CreateFromPem(issuingCaEntity.X509CertificatePem);
            }
            else
            {
                if (issuingCaEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(issuingCaEntity.PfxPassword))
                    return CsrIssuanceResult.Failure("Issuing CA does not have a private key. Import the PFX first.");

                issuingCert = X509CertificateLoader.LoadPkcs12(
                    issuingCaEntity.EncryptedPfxBytes, issuingCaEntity.PfxPassword, X509KeyStorageFlags.Exportable);
            }

            var hashAlg = profile.HashAlgorithm?.ToUpperInvariant() switch
            {
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

            // Reuse the existing extension builders via an equivalent issuance request. Subject DN
            // comes from the CSR; SANs are the authoritative set supplied by the caller (profile-driven).
            var extReq = new CertificateIssuanceRequest
            {
                IssuingCaCertificateId = request.IssuingCaCertificateId,
                ProfileId = request.ProfileId,
                TrustDomainId = request.TrustDomainId,
                SubjectDn = csr.SubjectName.Name,
                CertificateName = request.CertificateName,
                SubjectAltNames = request.SubjectAltNames,
                CdpUrls = request.CdpUrls,
                AiaUrls = request.AiaUrls,
                NotBefore = request.NotBefore,
                NotAfter = request.NotAfter,
            };

            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(profile.ValidityDays);
            if (notAfter > issuingCert.NotAfter)
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            bool isRsaSubject = csr.PublicKey.Oid.Value == "1.2.840.113549.1.1.1";

            X509Certificate2 cert;
            if (issuerKeyRef != null)
            {
                if (PqcAlgorithms.IsPqc(issuingCaEntity.KeyAlgorithm))
                    return CsrIssuanceResult.Failure(PqcAlgorithms.RemoteBlockedMessage);

                // Issuer signs remotely (Vault Transit / Cloud KMS). The subject public key is the CSR's.
                AsymmetricAlgorithm? subjectPublicKey =
                    (AsymmetricAlgorithm?)csr.PublicKey.GetRSAPublicKey()
                    ?? csr.PublicKey.GetECDsaPublicKey();
                if (subjectPublicKey == null)
                {
                    return CsrIssuanceResult.Failure(
                        "The CSR public key is post-quantum. Vault Transit and GCP KMS can only sign RSA and ECDSA requests; use a local issuing CA.");
                }

                using (subjectPublicKey)
                {
                    var extensions = BuildExtensionsForRemote(profile, extReq, subjectPublicKey, issuingCert);
                    cert = await RemoteCertificateBuilder.CreateSignedAsync(
                        _signingProvider, issuerKeyRef, issuingCert, subjectPublicKey,
                        csr.SubjectName.Name, notBefore, notAfter, extensions, hashAlg);
                }
            }
            else
            {
                // Local issuer signing — the CSR public key can be classical or post-quantum.
                var certRequest = new CertificateRequest(
                    csr.SubjectName, csr.PublicKey, hashAlg,
                    isRsaSubject ? RSASignaturePadding.Pkcs1 : null);

                AddExtensions(certRequest, profile, extReq, issuingCert);

                var serialBytes = RandomNumberGenerator.GetBytes(16);
                var (generator, ownedKey) = OpenSignatureGenerator(issuingCert);
                using (ownedKey)
                {
                    cert = certRequest.Create(
                        issuingCert.SubjectName,
                        generator,
                        notBefore, notAfter, serialBytes);
                }
            }

            using (cert)
            {
                var issuerError = VerifyIssuedBy(cert, issuingCert);
                if (issuerError != null)
                    return CsrIssuanceResult.Failure(issuerError);

                var pem = cert.ExportCertificatePem();
                var chainPem = await BuildChainPemAsync(db, issuingCaEntity);

                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(csr.SubjectName.Name) ?? csr.SubjectName.Name
                    : request.CertificateName;

                var sanString = request.SubjectAltNames.Count > 0
                    ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                    : null;

                var issuedEntity = new IssuedCertificate
                {
                    IssuingCaCertificateId = request.IssuingCaCertificateId,
                    ProfileId = request.ProfileId,
                    Name = certName,
                    Subject = cert.Subject,
                    SubjectAltNames = sanString,
                    X509CertificatePem = pem,
                    EncryptedPfxBytes = null, // requester holds the private key — CA never sees it
                    PfxPassword = null,
                    Thumbprint = cert.Thumbprint,
                    SerialNumber = cert.SerialNumber,
                    KeyAlgorithm = PqcAlgorithms.DescribeCertificate(cert).Algorithm,
                    KeySize = PqcAlgorithms.DescribeCertificate(cert).KeySize,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    Version = renewalVersion,
                    RenewalOfId = renewalOfId,
                };

                db.IssuedCertificates.Add(issuedEntity);
                await db.SaveChangesAsync();

                return new CsrIssuanceResult
                {
                    Success = true,
                    EntityId = issuedEntity.Id,
                    EntityType = "IssuedCertificate",
                    Thumbprint = cert.Thumbprint,
                    SerialNumber = cert.SerialNumber,
                    CertificatePem = pem,
                    ChainPem = chainPem,
                };
            }
        }
        catch (Exception ex)
        {
            return CsrIssuanceResult.Failure($"CSR issuance failed: {ex.Message}");
        }
        finally
        {
            issuingCert?.Dispose();
        }
    }

    /// <summary>
    /// Builds a PEM chain from the issuing CA up to the root by following ParentId links.
    /// </summary>
    private static async Task<string?> BuildChainPemAsync(SigyllDbContext db, CaCertificate issuingCa)
    {
        var sb = new System.Text.StringBuilder();
        CaCertificate? current = issuingCa;
        var seen = new HashSet<int>();
        while (current != null && seen.Add(current.Id))
        {
            sb.AppendLine(current.X509CertificatePem.Trim());
            if (current.ParentId == null) break;
            current = await db.CaCertificates.FindAsync(current.ParentId.Value);
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }

    /// <summary>
    /// Re-signs an existing certificate with the same key pair but new serial and validity.
    /// The SKI remains the same so downstream certificate chains continue to validate.
    /// Creates a new certificate entity; the old one is preserved.
    /// </summary>
    public async Task<CertificateIssuanceResult> ResignCertificateAsync(CertificateResignRequest request)
    {
        var identity = await _operator.DemandAsync(Permission.Operate);
        var result = await ResignAsync(request);
        await RecordIssuanceAsync(identity, result.Success, result.EntityType, result.EntityId, result.SerialNumber,
            $"Re-signed {request.EntityType} #{request.ExistingCertificateId} with its existing key",
            $"{request.EntityType} #{request.ExistingCertificateId}", result.Error);
        return result;
    }

    private async Task<CertificateIssuanceResult> ResignAsync(CertificateResignRequest request)
    {

        if (string.IsNullOrWhiteSpace(request.PfxPassword))
            return CertificateIssuanceResult.Failure("PFX password is required.");

        await using var db = await _dbFactory.CreateDbContextAsync();

        // Currently only CA certificates can be re-signed (they have hierarchy)
        if (request.EntityType != "CaCertificate")
            return CertificateIssuanceResult.Failure("Only CA certificates can be re-signed.");

        var caEntity = await db.CaCertificates.FindAsync(request.ExistingCertificateId);
        if (caEntity == null)
            return CertificateIssuanceResult.Failure("Certificate not found.");

        if (caEntity.EncryptedPfxBytes == null || string.IsNullOrEmpty(caEntity.PfxPassword))
            return CertificateIssuanceResult.Failure("Certificate does not have a private key.");

        // Load existing cert with private key
        X509Certificate2 existingCert;
        try
        {
            existingCert = X509CertificateLoader.LoadPkcs12(
                caEntity.EncryptedPfxBytes,
                caEntity.PfxPassword,
                X509KeyStorageFlags.Exportable);
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Failed to load certificate: {ex.Message}");
        }

        // Load parent CA for signing (if not self-signed root)
        X509Certificate2? parentCert = null;
        bool isSelfSigned = caEntity.ParentId == null;

        if (!isSelfSigned)
        {
            var parentEntity = await db.CaCertificates.FindAsync(caEntity.ParentId);
            if (parentEntity?.EncryptedPfxBytes == null || string.IsNullOrEmpty(parentEntity.PfxPassword))
            {
                existingCert.Dispose();
                return CertificateIssuanceResult.Failure("Parent CA does not have a private key.");
            }

            try
            {
                parentCert = X509CertificateLoader.LoadPkcs12(
                    parentEntity.EncryptedPfxBytes,
                    parentEntity.PfxPassword,
                    X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                existingCert.Dispose();
                return CertificateIssuanceResult.Failure($"Failed to load parent CA: {ex.Message}");
            }
        }

        try
        {
            // Build CertificateRequest using the SAME key from the existing cert
            var rsaKey = existingCert.GetRSAPrivateKey();
            var ecdsaKey = existingCert.GetECDsaPrivateKey();
            using var pqcKey = PqcKeyPair.FromCertificate(existingCert);

            CertificateRequest certRequest;
            if (pqcKey != null)
            {
                certRequest = pqcKey.CreateCertificateRequest(existingCert.SubjectName);
            }
            else if (ecdsaKey != null)
            {
                certRequest = new CertificateRequest(
                    existingCert.SubjectName,
                    ecdsaKey,
                    HashAlgorithmName.SHA256);
            }
            else if (rsaKey != null)
            {
                certRequest = new CertificateRequest(
                    existingCert.SubjectName,
                    rsaKey,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            else
            {
                return CertificateIssuanceResult.Failure("Unsupported key algorithm.");
            }

            // Copy ALL extensions from the existing certificate
            // This preserves SKI, AKI, BasicConstraints, KeyUsage, SANs, CDP, AIA, etc.
            foreach (var ext in existingCert.Extensions)
            {
                certRequest.CertificateExtensions.Add(ext);
            }

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var originalDuration = existingCert.NotAfter - existingCert.NotBefore;
            var notAfter = request.NotAfter ?? notBefore.Add(originalDuration);

            // Clamp to parent's NotAfter
            if (parentCert != null && notAfter > parentCert.NotAfter)
            {
                notAfter = new DateTimeOffset(parentCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
            }

            X509Certificate2 newCert;
            IDisposable? signatureKey = null;
            try
            {
                if (isSelfSigned)
                {
                    newCert = certRequest.CreateSelfSigned(notBefore, notAfter);
                }
                else
                {
                    var serialBytes = RandomNumberGenerator.GetBytes(16);
                    var (generator, ownedKey) = OpenSignatureGenerator(parentCert!);
                    signatureKey = ownedKey;
                    using var signedCert = certRequest.Create(
                        parentCert!.SubjectName,
                        generator,
                        notBefore,
                        notAfter,
                        serialBytes);

                    if (pqcKey != null)
                        newCert = pqcKey.CopyWithPrivateKey(signedCert);
                    else if (ecdsaKey != null)
                        newCert = signedCert.CopyWithPrivateKey(ecdsaKey);
                    else
                        newCert = signedCert.CopyWithPrivateKey(rsaKey!);
                }
            }
            finally
            {
                signatureKey?.Dispose();
            }

            using (newCert)
            {
                // Verify the re-signed cert is actually signed by the parent CA
                if (!isSelfSigned)
                {
                    var issuerError = VerifyIssuedBy(newCert, parentCert!);
                    if (issuerError != null)
                        return CertificateIssuanceResult.Failure(issuerError);
                }

                var pfxBytes = Pkcs12Writer.Write(newCert, request.PfxPassword);
                var pem = newCert.ExportCertificatePem();

                // Update the existing entity in-place so all child relationships
                // (issued certs, CRLs, sub-CAs) remain attached to this CA.
                _logger.LogInformation("Re-sign: updating CA entity Id={Id} in-place (EntityState={State})",
                    caEntity.Id, db.Entry(caEntity).State);

                caEntity.X509CertificatePem = pem;
                caEntity.EncryptedPfxBytes = pfxBytes;
                caEntity.PfxPassword = request.PfxPassword;
                caEntity.Thumbprint = newCert.Thumbprint;
                caEntity.SerialNumber = newCert.SerialNumber;
                caEntity.NotBefore = newCert.NotBefore.ToUniversalTime();
                caEntity.NotAfter = newCert.NotAfter.ToUniversalTime();

                _logger.LogInformation("Re-sign: after property update EntityState={State}, NotAfter={NotAfter}",
                    db.Entry(caEntity).State, caEntity.NotAfter);

                await db.SaveChangesAsync();

                _logger.LogInformation("Re-sign: SaveChanges complete for CA Id={Id}", caEntity.Id);

                return new CertificateIssuanceResult
                {
                    Success = true,
                    EntityId = caEntity.Id,
                    EntityType = "CaCertificate",
                    Thumbprint = newCert.Thumbprint,
                    SerialNumber = newCert.SerialNumber
                };
            }
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Re-sign failed: {ex.Message}");
        }
        finally
        {
            existingCert.Dispose();
            parentCert?.Dispose();
        }
    }

    /// <summary>
    /// Issues a certificate using a remote signing provider (Vault Transit, Cloud KMS).
    /// Uses BouncyCastle's X509V3CertificateGenerator with a pluggable ISignatureFactory
    /// so the private key never leaves the provider boundary.
    /// </summary>
    private async Task<CertificateIssuanceResult> IssueCertificateRemoteAsync(
        SigyllDbContext db,
        CertificateProfile profile,
        CertificateIssuanceRequest request,
        bool isSelfSigned,
        X509Certificate2? issuingCert,
        CaCertificate? issuingCaEntity,
        SigningKeyReference? issuerKeyRef,
        int renewalVersion,
        int? renewalOfId)
    {
        try
        {
            var hashAlg = profile.HashAlgorithm?.ToUpperInvariant() switch
            {
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

            // Generate new key in the remote provider
            var newKeyRef = await _signingProvider.GenerateKeyAsync(
                profile.KeyAlgorithm, profile.KeySize, profile.EcdsaCurve);

            // Get the public key to build extensions
            using var publicKey = await _signingProvider.GetPublicKeyAsync(newKeyRef);

            // Build extensions using the same logic as local path
            var extensions = BuildExtensionsForRemote(profile, request, publicKey, issuingCert);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(profile.ValidityDays);
            if (issuingCert != null && notAfter > issuingCert.NotAfter)
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            // For self-signed: sign with own key. For CA-signed: sign with issuer's key.
            var signingKeyRef = isSelfSigned ? newKeyRef : (issuerKeyRef ?? newKeyRef);

            X509Certificate2 cert;
            if (isSelfSigned)
            {
                cert = await RemoteCertificateBuilder.CreateSelfSignedAsync(
                    _signingProvider, signingKeyRef, request.SubjectDn,
                    notBefore, notAfter, extensions, hashAlg);
            }
            else
            {
                cert = await RemoteCertificateBuilder.CreateSignedAsync(
                    _signingProvider, signingKeyRef, issuingCert!,
                    publicKey, request.SubjectDn,
                    notBefore, notAfter, extensions, hashAlg);
            }

            using (cert)
            {
                // Verify issuer relationship
                if (!isSelfSigned)
                {
                    var issuerError = VerifyIssuedBy(cert, issuingCert!);
                    if (issuerError != null)
                        return CertificateIssuanceResult.Failure(issuerError);
                }

                var pem = cert.ExportCertificatePem();
                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                int keySize = GetKeySize(cert);
                bool isCaType = profile.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        TrustDomainId = request.TrustDomainId,
                        ParentId = isSelfSigned ? null : request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = cert.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = null, // No PFX — key is in Vault
                        PfxPassword = null,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = profile.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrls.Count > 0 ? string.Join(";", request.CdpUrls) : null,
                        AuthorityInfoAccessUri = request.AiaUrls.Count > 0 ? string.Join(";", request.AiaUrls) : null,
                        CertSecurityLevel = CertSecurityLevel.CloudKms,
                        StoreProviderHint = $"{_signingProvider.ProviderName}:{newKeyRef.KeyIdentifier}",
                        Version = renewalVersion,
                        RenewalOfId = renewalOfId,
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    await PublishCaCertAndCrlAsync(request.TrustDomainId, certName, cert.RawData);

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        ProfileId = request.ProfileId,
                        Name = certName,
                        Subject = cert.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = null, // No PFX — key is in Vault
                        PfxPassword = null,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        KeyAlgorithm = profile.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = cert.NotBefore.ToUniversalTime(),
                        NotAfter = cert.NotAfter.ToUniversalTime(),
                        CertSecurityLevel = CertSecurityLevel.CloudKms,
                        StoreProviderHint = $"{_signingProvider.ProviderName}:{newKeyRef.KeyIdentifier}",
                        Version = renewalVersion,
                        RenewalOfId = renewalOfId,
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex) when (ex.Message.Contains("signing key not found", StringComparison.OrdinalIgnoreCase))
        {
            return CertificateIssuanceResult.Failure(
                "The issuing CA's signing key is missing from Vault Transit. " +
                "This usually means Vault was restarted (dev mode stores keys in memory and wipes them on restart). " +
                "Re-create the issuing CA, or run Vault with persistent storage.");
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Remote certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert?.Dispose();
        }
    }

    /// <summary>
    /// Issues a certificate with a LOCAL private key but signed by a REMOTE provider (Vault Transit).
    /// This is the hybrid path: the end-entity gets a PFX (exportable private key),
    /// while the issuing CA's signature comes from the remote signing provider.
    /// </summary>
    private async Task<CertificateIssuanceResult> IssueCertificateHybridAsync(
        SigyllDbContext db,
        CertificateProfile profile,
        CertificateIssuanceRequest request,
        X509Certificate2 issuingCert,
        CaCertificate issuingCaEntity,
        SigningKeyReference issuerKeyRef,
        int renewalVersion,
        int? renewalOfId)
    {
        try
        {
            var hashAlg = profile.HashAlgorithm?.ToUpperInvariant() switch
            {
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

            // Generate key pair LOCALLY
            using var keyHolder = GenerateKeyPair(profile);
            AsymmetricAlgorithm localKey = (AsymmetricAlgorithm?)keyHolder.Ecdsa ?? keyHolder.Rsa!;

            // Build extensions using local public key
            var extensions = BuildExtensionsForRemote(profile, request, localKey, issuingCert);

            // Determine validity
            var notBefore = request.NotBefore ?? DateTimeOffset.UtcNow;
            var notAfter = request.NotAfter ?? notBefore.AddDays(profile.ValidityDays);
            if (notAfter > issuingCert.NotAfter)
                notAfter = new DateTimeOffset(issuingCert.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            // Sign via remote provider (issuer's key is in Vault) but subject key is local
            var cert = await RemoteCertificateBuilder.CreateSignedAsync(
                _signingProvider, issuerKeyRef, issuingCert,
                localKey, request.SubjectDn,
                notBefore, notAfter, extensions, hashAlg);

            // Attach the LOCAL private key so we can export as PFX
            X509Certificate2 certWithKey;
            if (keyHolder.Ecdsa != null)
                certWithKey = cert.CopyWithPrivateKey(keyHolder.Ecdsa);
            else
                certWithKey = cert.CopyWithPrivateKey(keyHolder.Rsa!);
            cert.Dispose();

            using (certWithKey)
            {
                // Verify issuer relationship
                var issuerError = VerifyIssuedBy(certWithKey, issuingCert);
                if (issuerError != null)
                    return CertificateIssuanceResult.Failure(issuerError);

                var pfxBytes = Pkcs12Writer.Write(certWithKey, request.PfxPassword);
                var pem = certWithKey.ExportCertificatePem();

                var certName = string.IsNullOrWhiteSpace(request.CertificateName)
                    ? ExtractCnFromDn(request.SubjectDn) ?? request.SubjectDn
                    : request.CertificateName;

                int keySize = GetKeySize(certWithKey);
                bool isCaType = profile.CertificateType is CertificateType.RootCa or CertificateType.IntermediateCa;

                if (isCaType)
                {
                    var caEntity = new CaCertificate
                    {
                        TrustDomainId = request.TrustDomainId,
                        ParentId = request.IssuingCaCertificateId,
                        Name = certName,
                        Subject = certWithKey.Subject,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber,
                        KeyAlgorithm = profile.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = certWithKey.NotBefore.ToUniversalTime(),
                        NotAfter = certWithKey.NotAfter.ToUniversalTime(),
                        CrlDistributionPoint = request.CdpUrls.Count > 0 ? string.Join(";", request.CdpUrls) : null,
                        AuthorityInfoAccessUri = request.AiaUrls.Count > 0 ? string.Join(";", request.AiaUrls) : null,
                        Version = renewalVersion,
                        RenewalOfId = renewalOfId,
                        // Local key — standard software level, no provider hint
                    };

                    db.CaCertificates.Add(caEntity);
                    await db.SaveChangesAsync();

                    await PublishCaCertAndCrlAsync(request.TrustDomainId, certName, certWithKey.RawData);

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = caEntity.Id,
                        EntityType = "CaCertificate",
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber
                    };
                }
                else
                {
                    var sanString = request.SubjectAltNames.Count > 0
                        ? string.Join(";", request.SubjectAltNames.Select(s => $"{s.Type}:{s.Value}"))
                        : null;

                    var issuedEntity = new IssuedCertificate
                    {
                        IssuingCaCertificateId = request.IssuingCaCertificateId!.Value,
                        ProfileId = request.ProfileId,
                        Name = certName,
                        Subject = certWithKey.Subject,
                        SubjectAltNames = sanString,
                        X509CertificatePem = pem,
                        EncryptedPfxBytes = pfxBytes,
                        PfxPassword = request.PfxPassword,
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber,
                        KeyAlgorithm = profile.KeyAlgorithm,
                        KeySize = keySize,
                        NotBefore = certWithKey.NotBefore.ToUniversalTime(),
                        NotAfter = certWithKey.NotAfter.ToUniversalTime(),
                        Version = renewalVersion,
                        RenewalOfId = renewalOfId,
                        // Local key — no StoreProviderHint, standard security level
                    };

                    db.IssuedCertificates.Add(issuedEntity);
                    await db.SaveChangesAsync();

                    return new CertificateIssuanceResult
                    {
                        Success = true,
                        EntityId = issuedEntity.Id,
                        EntityType = "IssuedCertificate",
                        Thumbprint = certWithKey.Thumbprint,
                        SerialNumber = certWithKey.SerialNumber
                    };
                }
            }
        }
        catch (Exception ex) when (ex.Message.Contains("signing key not found", StringComparison.OrdinalIgnoreCase))
        {
            return CertificateIssuanceResult.Failure(
                "The new certificate's signing key is missing from Vault Transit. " +
                "This usually means Vault was restarted (dev mode stores keys in memory and wipes them on restart). " +
                "Re-create the certificate, or run Vault with persistent storage.");
        }
        catch (Exception ex)
        {
            return CertificateIssuanceResult.Failure($"Hybrid certificate generation failed: {ex.Message}");
        }
        finally
        {
            issuingCert.Dispose();
        }
    }

    /// <summary>
    /// Builds X509Extensions for the remote signing path using .NET's extension types.
    /// These are later converted to BouncyCastle format by RemoteCertificateBuilder.
    /// </summary>
    private static X509Extension[] BuildExtensionsForRemote(
        CertificateProfile profile,
        CertificateIssuanceRequest request,
        AsymmetricAlgorithm subjectPublicKey,
        X509Certificate2? issuingCert)
    {
        var extensions = new List<X509Extension>();

        // BasicConstraints
        bool hasPathLength = profile.IsBasicConstraintsCa && profile.PathLengthConstraint.HasValue;
        extensions.Add(new X509BasicConstraintsExtension(
            profile.IsBasicConstraintsCa,
            hasPathLength,
            hasPathLength ? profile.PathLengthConstraint!.Value : 0,
            profile.IsBasicConstraintsCritical));

        // Key Usage
        var keyUsage = (X509KeyUsageFlags)profile.KeyUsageFlags;
        extensions.Add(new X509KeyUsageExtension(keyUsage, profile.IsKeyUsageCritical));

        // Subject Key Identifier — need a temporary CertificateRequest to get the PublicKey
        var tempRequest = subjectPublicKey is ECDsa ecdsa
            ? new CertificateRequest("CN=temp", ecdsa, HashAlgorithmName.SHA256)
            : new CertificateRequest("CN=temp", (RSA)subjectPublicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        extensions.Add(new X509SubjectKeyIdentifierExtension(tempRequest.PublicKey, false));

        // Authority Key Identifier
        if (issuingCert != null)
        {
            CertificateExtensionHelpers.AddAuthorityKeyIdentifierToList(issuingCert, extensions);
        }

        // Extended Key Usage
        if (!string.IsNullOrWhiteSpace(profile.ExtendedKeyUsageOids))
        {
            var oids = new OidCollection();
            foreach (var oid in profile.ExtendedKeyUsageOids.Split(';',
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                oids.Add(new Oid(oid));
            if (oids.Count > 0)
                extensions.Add(new X509EnhancedKeyUsageExtension(oids, profile.IsExtendedKeyUsageCritical));
        }

        // CDP
        if (profile.IncludeCdp && request.CdpUrls.Count > 0)
            extensions.Add(CertificateExtensionHelpers.MakeCdp(request.CdpUrls));

        // AIA
        if (profile.IncludeAia && request.AiaUrls.Count > 0)
            extensions.Add(CertificateExtensionHelpers.BuildAiaExtension(
                request.AiaUrls.Select(u => new Uri(u)).ToList()));

        // SANs — built via BouncyCastle so URI text is preserved exactly (no trailing-slash normalisation)
        if (request.SubjectAltNames.Count > 0)
        {
            var sanExtension = SanExtensionBuilder.Build(request.SubjectAltNames);
            if (sanExtension != null)
                extensions.Add(sanExtension);
        }

        return extensions.ToArray();
    }

    /// <summary>
    /// Verifies that <paramref name="cert"/> was signed by <paramref name="issuer"/>
    /// using BouncyCastle signature verification. Returns null on success or an error message.
    /// </summary>
    public static string? VerifyIssuedBy(X509Certificate2 cert, X509Certificate2 issuer)
    {
        var pqc = PqcCertificateVerifier.TryVerify(cert.RawData, issuer.RawData);
        if (pqc == true) return null;
        if (pqc == false)
            return "Certificate signature verification failed: the certificate was not signed by the specified CA.";

        try
        {
            var bcParser = new Org.BouncyCastle.X509.X509CertificateParser();
            var bcCert = bcParser.ReadCertificate(cert.RawData);
            var bcIssuer = bcParser.ReadCertificate(issuer.RawData);

            // Check Issuer DN matches Subject DN of the alleged issuer
            if (!bcCert.IssuerDN.Equivalent(bcIssuer.SubjectDN))
            {
                return $"Certificate Issuer DN '{bcCert.IssuerDN}' does not match the CA Subject DN '{bcIssuer.SubjectDN}'.";
            }

            // Verify the signature
            bcCert.Verify(bcIssuer.GetPublicKey());
            return null; // success
        }
        catch (Org.BouncyCastle.Security.InvalidKeyException)
        {
            return "Certificate signature verification failed: the certificate was not signed by the specified CA.";
        }
        catch (Org.BouncyCastle.Security.Certificates.CertificateException ex)
        {
            return $"Certificate signature verification failed: {ex.Message}";
        }
        catch (Exception ex)
        {
            return $"Certificate issuer validation failed: {ex.Message}";
        }
    }

    private static KeyHolder GenerateKeyPair(CertificateProfile profile)
    {
        var pqcId = PqcAlgorithms.Canonicalize(profile.KeyAlgorithm, profile.KeySize);
        if (pqcId != null)
            return new KeyHolder(pqc: PqcKeyPair.Generate(pqcId));

        if (profile.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = profile.EcdsaCurve?.ToLowerInvariant() switch
            {
                "nistp256" => ECCurve.NamedCurves.nistP256,
                "nistp384" => ECCurve.NamedCurves.nistP384,
                "nistp521" => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP384 // default
            };

            return new KeyHolder(ecdsa: ECDsa.Create(curve));
        }

        return new KeyHolder(rsa: RSA.Create(profile.KeySize));
    }

    private static CertificateRequest CreateCertificateRequest(
        CertificateProfile profile,
        string subjectDn,
        KeyHolder keyHolder)
    {
        subjectDn = DistinguishedNameText.Normalize(subjectDn);
        if (keyHolder.Pqc != null)
            return keyHolder.Pqc.CreateCertificateRequest(subjectDn);

        var hashAlg = profile.HashAlgorithm?.ToUpperInvariant() switch
        {
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };

        if (keyHolder.Ecdsa != null)
        {
            return new CertificateRequest(subjectDn, keyHolder.Ecdsa, hashAlg);
        }

        return new CertificateRequest(
            subjectDn,
            keyHolder.Rsa!,
            hashAlg,
            RSASignaturePadding.Pkcs1);
    }

    private static void AddExtensions(
        CertificateRequest certRequest,
        CertificateProfile profile,
        CertificateIssuanceRequest request,
        X509Certificate2? issuingCert)
    {
        // Basic Constraints
        bool hasPathLength = profile.IsBasicConstraintsCa && profile.PathLengthConstraint.HasValue;
        certRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                profile.IsBasicConstraintsCa,
                hasPathLength,
                hasPathLength ? profile.PathLengthConstraint!.Value : 0,
                profile.IsBasicConstraintsCritical));

        // Key Usage
        var keyUsage = (X509KeyUsageFlags)profile.KeyUsageFlags;
        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(keyUsage, profile.IsKeyUsageCritical));

        // Subject Key Identifier
        certRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));

        // Authority Key Identifier (if issued by a CA)
        if (issuingCert != null)
        {
            CertificateExtensionHelpers.AddAuthorityKeyIdentifier(issuingCert, certRequest);
        }

        // Extended Key Usage
        if (!string.IsNullOrWhiteSpace(profile.ExtendedKeyUsageOids))
        {
            var oids = new OidCollection();
            foreach (var oid in profile.ExtendedKeyUsageOids.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                oids.Add(new Oid(oid));
            }

            if (oids.Count > 0)
            {
                certRequest.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(oids, profile.IsExtendedKeyUsageCritical));
            }
        }

        // CRL Distribution Points
        if (profile.IncludeCdp && request.CdpUrls.Count > 0)
        {
            certRequest.CertificateExtensions.Add(
                CertificateExtensionHelpers.MakeCdp(request.CdpUrls));
        }

        // Authority Information Access
        if (profile.IncludeAia && request.AiaUrls.Count > 0)
        {
            certRequest.CertificateExtensions.Add(
                CertificateExtensionHelpers.BuildAiaExtension(
                    request.AiaUrls.Select(u => new Uri(u)).ToList()));
        }

        // Subject Alternative Names — built via BouncyCastle so URI text is preserved exactly
        if (request.SubjectAltNames.Count > 0)
        {
            var sanExtension = SanExtensionBuilder.Build(request.SubjectAltNames);
            if (sanExtension != null)
                certRequest.CertificateExtensions.Add(sanExtension);
        }
    }

    private static (X509SignatureGenerator Generator, IDisposable? OwnedKey) OpenSignatureGenerator(X509Certificate2 issuerCert)
    {
        var pqc = PqcKeyPair.SignatureGeneratorFor(issuerCert);
        if (pqc != null)
            return (pqc.Value.Generator, pqc.Value.Key);

        if (issuerCert.GetECDsaPrivateKey() is { } ecdsa)
            return (X509SignatureGenerator.CreateForECDsa(ecdsa), ecdsa);

        if (issuerCert.GetRSAPrivateKey() is { } rsa)
            return (X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1), rsa);

        throw new InvalidOperationException(
            $"Unsupported issuer key algorithm: {issuerCert.PublicKey.Oid.FriendlyName ?? issuerCert.PublicKey.Oid.Value}");
    }

    private static CertificateRequest LoadSigningRequest(string pem)
    {
        Exception? last = null;
        foreach (var hash in new[] { HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 })
        {
            try
            {
                return CertificateRequest.LoadSigningRequestPem(pem, hash);
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException)
            {
                last = ex;
            }
        }

        throw last ?? new CryptographicException("The CSR could not be read.");
    }

    private static X509Certificate2 AttachPrivateKey(X509Certificate2 signedCert, KeyHolder keyHolder)
    {
        // Windows cannot attach an ML-KEM key to a certificate; ExportPfx writes it from the key holder.
        if (keyHolder.Pqc is { CanSign: false })
            return X509CertificateLoader.LoadCertificate(signedCert.RawData);
        if (keyHolder.Pqc != null)
            return keyHolder.Pqc.CopyWithPrivateKey(signedCert);
        if (keyHolder.Ecdsa != null)
            return signedCert.CopyWithPrivateKey(keyHolder.Ecdsa);

        return signedCert.CopyWithPrivateKey(keyHolder.Rsa!);
    }

    private static byte[] ExportPfx(X509Certificate2 cert, KeyHolder keyHolder, string password) =>
        keyHolder.Pqc is { CanSign: false } kem
            ? Pkcs12Writer.Write(cert, kem, password)
            : Pkcs12Writer.Write(cert, password);

    private async Task PublishCaCertAndCrlAsync(
        int trustDomainId, string certName, byte[] certDerBytes)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var baseUrls = await db.TrustDomainBaseUrls
            .Where(bu => bu.TrustDomainId == trustDomainId && bu.PublishingBasePath != null)
            .ToListAsync();

        if (baseUrls.Count == 0) return;

        foreach (var baseUrl in baseUrls)
        {
            if (string.IsNullOrEmpty(baseUrl.PublishingBasePath)) continue;

            try
            {
                var certPath = _publishingPaths.Resolve(baseUrl.PublishingBasePath, "certs", $"{certName}.cer");
                var certDir = Path.GetDirectoryName(certPath);
                if (!string.IsNullOrEmpty(certDir))
                    Directory.CreateDirectory(certDir);

                var tempPath = certPath + ".tmp";
                await File.WriteAllBytesAsync(tempPath, certDerBytes);
                File.Move(tempPath, certPath, overwrite: true);
                _logger.LogInformation("Published certificate to {Path} ({Bytes} bytes)", certPath, certDerBytes.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to publish certificate for CA '{CertName}'", certName);
            }
        }
    }

    private static int GetKeySize(X509Certificate2 cert)
    {
        if (cert.GetECDsaPublicKey() is { } ecdsa)
        {
            using (ecdsa)
                return ecdsa.KeySize;
        }

        if (cert.GetRSAPublicKey() is { } rsa)
        {
            using (rsa)
                return rsa.KeySize;
        }

        return 0;
    }

    private static string? ExtractCnFromDn(string dn)
    {
        // Simple CN extraction from "CN=value, O=..."
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed[3..].Trim();
        }

        return null;
    }

    /// <summary>
    /// Holds the generated key pair and disposes it after the certificate has been exported.
    /// </summary>
    private sealed class KeyHolder : IDisposable
    {
        public RSA? Rsa { get; }
        public ECDsa? Ecdsa { get; }
        public PqcKeyPair? Pqc { get; }

        public KeyHolder(RSA? rsa = null, ECDsa? ecdsa = null, PqcKeyPair? pqc = null)
        {
            Rsa = rsa;
            Ecdsa = ecdsa;
            Pqc = pqc;
        }

        public void Dispose()
        {
            Rsa?.Dispose();
            Ecdsa?.Dispose();
            Pqc?.Dispose();
        }
    }
}
