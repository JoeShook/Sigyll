#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services.Pqc;
using Sigyll.Common.ViewModels;

namespace Sigyll.Common.Services;

/// <summary>
/// Direct secure messaging with post-quantum keys. An RSA Direct certificate both signs and
/// decrypts; ML-DSA only signs and ML-KEM only encapsulates, so each Direct address (or domain)
/// needs two certificates. This service issues them together, bound to the same rfc822Name or
/// dNSName by the same CA, with the encryption certificate pointing at its signing partner
/// through an RFC 9763 RelatedCertificate extension, and proves the pair with a sign-encrypt-
/// decrypt-verify round trip.
/// </summary>
public class DirectPqcPairService
{
    private const string EmailProtectionOid = "1.3.6.1.5.5.7.3.4";
    private static readonly Oid Sha512 = new("2.16.840.1.101.3.4.2.3");

    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly CertificateIssuanceService _issuance;
    private readonly ChainValidationService _chainValidation;
    private readonly ILogger<DirectPqcPairService> _logger;

    public DirectPqcPairService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        CertificateIssuanceService issuance,
        ChainValidationService chainValidation,
        ILogger<DirectPqcPairService> logger)
    {
        _dbFactory = dbFactory;
        _issuance = issuance;
        _chainValidation = chainValidation;
        _logger = logger;
    }

    /// <summary>Templates that can be the signing half: end-entity, signature key, digitalSignature, no keyEncipherment.</summary>
    public static bool IsSigningTemplate(CertificateTemplate t) =>
        t.CertificateType is CertificateType.EndEntityClient or CertificateType.EndEntityServer
        && PqcAlgorithms.IsPqc(t.KeyAlgorithm) && !PqcAlgorithms.IsKem(t.KeyAlgorithm, t.KeySize)
        && HasUsage(t, X509KeyUsageFlags.DigitalSignature) && !HasUsage(t, X509KeyUsageFlags.KeyEncipherment);

    /// <summary>Templates that can be the encryption half: end-entity ML-KEM with keyEncipherment and nothing else.</summary>
    public static bool IsEncryptionTemplate(CertificateTemplate t) =>
        t.CertificateType is CertificateType.EndEntityClient or CertificateType.EndEntityServer
        && PqcAlgorithms.IsKem(t.KeyAlgorithm, t.KeySize)
        && (X509KeyUsageFlags)t.KeyUsageFlags == X509KeyUsageFlags.KeyEncipherment;

    public async Task<DirectPairResult> IssuePairAsync(DirectPairRequest request, CancellationToken ct = default)
    {
        var identifier = request.Identifier.Trim();
        var bindingError = ValidateIdentifier(request.Binding, identifier);
        if (bindingError != null)
            return DirectPairResult.Failure(bindingError);

        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            var signing = await db.CertificateTemplates.FindAsync([request.SigningTemplateId], ct);
            var encryption = await db.CertificateTemplates.FindAsync([request.EncryptionTemplateId], ct);
            if (signing == null || !IsSigningTemplate(signing))
                return DirectPairResult.Failure(
                    "The signing template must be an end-entity ML-DSA, SLH-DSA or composite template with digitalSignature and without keyEncipherment.");
            if (encryption == null || !IsEncryptionTemplate(encryption))
                return DirectPairResult.Failure(
                    "The encryption template must be an end-entity ML-KEM template whose only key usage is keyEncipherment.");
        }

        var san = new SanEntry(request.Binding == DirectBinding.Address ? SanType.Email : SanType.Dns, identifier);
        var subjectDn = string.IsNullOrWhiteSpace(request.SubjectDn) ? $"CN={identifier}" : request.SubjectDn.Trim();

        var signingResult = await _issuance.IssueCertificateAsync(Request(request.SigningTemplateId, $"{identifier} (signing)", null));
        if (!signingResult.Success)
            return DirectPairResult.Failure($"Signing certificate: {signingResult.Error}");

        var encryptionResult = await _issuance.IssueCertificateAsync(
            Request(request.EncryptionTemplateId, $"{identifier} (encryption)", signingResult.EntityId));
        if (!encryptionResult.Success)
        {
            // Never leave half a pair behind.
            await using var db = await _dbFactory.CreateDbContextAsync(ct);
            var orphan = await db.IssuedCertificates.FindAsync([signingResult.EntityId!.Value], ct);
            if (orphan != null)
            {
                db.IssuedCertificates.Remove(orphan);
                await db.SaveChangesAsync(ct);
            }
            return DirectPairResult.Failure($"Encryption certificate: {encryptionResult.Error}");
        }

        _logger.LogInformation("Direct PQC pair issued for {Identifier}: signing {SigningId}, encryption {EncryptionId}",
            identifier, signingResult.EntityId, encryptionResult.EntityId);

        return new DirectPairResult
        {
            Success = true,
            SigningCertificateId = signingResult.EntityId,
            EncryptionCertificateId = encryptionResult.EntityId,
        };

        CertificateIssuanceRequest Request(int templateId, string name, int? relatedId) => new()
        {
            IssuingCaCertificateId = request.IssuingCaCertificateId,
            TemplateId = templateId,
            TrustDomainId = request.TrustDomainId,
            SubjectDn = subjectDn,
            CertificateName = name,
            SubjectAltNames = [san],
            CdpUrls = request.CdpUrls,
            AiaUrls = request.AiaUrls,
            PfxPassword = request.PfxPassword,
            SigningProviderOverride = "local",
            RelatedCertificateId = relatedId,
        };
    }

    /// <summary>
    /// Proves a pair works the way a Direct HISP would use it: sign a message with the ML-DSA key,
    /// encrypt it to the ML-KEM certificate (CMS KEMRecipientInfo), decrypt with the ML-KEM key,
    /// verify the signature, and check the sender matches the certificates.
    /// </summary>
    public async Task<DirectRoundTripResult> RunRoundTripAsync(int signingCertificateId, int encryptionCertificateId, CancellationToken ct = default)
    {
        var result = new DirectRoundTripResult();
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var signingRow = await db.IssuedCertificates.FindAsync([signingCertificateId], ct);
        var encryptionRow = await db.IssuedCertificates.FindAsync([encryptionCertificateId], ct);
        if (signingRow?.EncryptedPfxBytes == null || encryptionRow?.EncryptedPfxBytes == null)
            return result.Fail("Load the pair", "Both certificates must exist and hold their private keys.");

        using var signingCert = X509Certificate2.CreateFromPem(signingRow.X509CertificatePem);
        using var encryptionCert = X509Certificate2.CreateFromPem(encryptionRow.X509CertificatePem);

        // 1. Same identity, same CA
        var signingSans = SanValues(signingCert);
        var encryptionSans = SanValues(encryptionCert);
        var identity = signingSans.FirstOrDefault();
        var sameIdentity = identity != null && signingSans.SetEquals(encryptionSans)
            && signingCert.IssuerName.RawData.AsSpan().SequenceEqual(encryptionCert.IssuerName.RawData)
            && signingRow.IssuingCaCertificateId == encryptionRow.IssuingCaCertificateId;
        if (!result.Step("Bound to one identity", sameIdentity,
                sameIdentity ? $"Both carry {identity} and were issued by {signingCert.Issuer}."
                             : "The SANs or issuers differ."))
            return result;

        // 2. Key usage split
        var signingUsage = KeyUsage(signingCert);
        var encryptionUsage = KeyUsage(encryptionCert);
        var usageOk = signingUsage.HasFlag(X509KeyUsageFlags.DigitalSignature)
                      && !signingUsage.HasFlag(X509KeyUsageFlags.KeyEncipherment)
                      && encryptionUsage == X509KeyUsageFlags.KeyEncipherment
                      && PqcAlgorithms.IsKem(PqcAlgorithms.DescribeCertificate(encryptionCert).Algorithm);
        if (!result.Step("Key usage split", usageOk,
                $"Signing: {PqcAlgorithms.DescribeCertificate(signingCert).Algorithm}, {signingUsage}. " +
                $"Encryption: {PqcAlgorithms.DescribeCertificate(encryptionCert).Algorithm}, {encryptionUsage}."))
            return result;

        // 3. RFC 9763 link
        var linked = CertificateExtensionHelpers.IsRelatedTo(encryptionCert, signingCert.RawData);
        if (!result.Step("RFC 9763 link", linked,
                linked ? "The encryption certificate's RelatedCertificate hash matches the signing certificate (SHA-256)."
                       : "The encryption certificate does not point at this signing certificate."))
            return result;

        // 4. Chains
        foreach (var (row, label) in new[] { (signingRow, "signing"), (encryptionRow, "encryption") })
        {
            var chain = await _chainValidation.ValidateIssuedCertificateAsync(row.Id, ct);
            if (!result.Step($"Chain ({label})", chain.IsValid,
                    chain.IsValid ? $"Trusted: {string.Join(" → ", chain.ChainLinks.Select(l => l.Name))}."
                                  : chain.Error ?? string.Join("; ", chain.ChainLinks.SelectMany(l => l.Problems))))
                return result;
        }

        var sender = identity!.Contains('@') ? identity : $"hisp@{identity}";
        var message = Encoding.UTF8.GetBytes(
            $"From: {sender}\r\nTo: {sender}\r\nSubject: Sigyll Direct PQC round trip\r\n" +
            $"Content-Type: text/plain; charset=utf-8\r\n\r\nSent {DateTimeOffset.UtcNow:O} with post-quantum keys.\r\n");

        // 5. Sign
        byte[] signed;
        try
        {
            using var signer = X509CertificateLoader.LoadPkcs12(signingRow.EncryptedPfxBytes, signingRow.PfxPassword,
                X509KeyStorageFlags.EphemeralKeySet);
            var cms = new SignedCms(new ContentInfo(message));
            cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signer)
            {
                DigestAlgorithm = Sha512,
                IncludeOption = X509IncludeOption.EndCertOnly,
            });
            signed = cms.Encode();
        }
        catch (Exception ex)
        {
            return result.Fail("Sign (ML-DSA)", ex.Message);
        }
        result.Step("Sign (ML-DSA)", true, $"CMS SignedData, {signed.Length:N0} bytes, digest SHA-512.");

        // 6. Encrypt
        byte[] enveloped;
        try
        {
            enveloped = KemEnvelopedData.Encrypt(signed, encryptionCert);
        }
        catch (Exception ex)
        {
            return result.Fail("Encrypt (ML-KEM)", ex.Message);
        }
        result.Step("Encrypt (ML-KEM)", true,
            $"CMS EnvelopedData with KEMRecipientInfo (RFC 9629): HKDF-SHA256, AES-256 key wrap, AES-256-CBC; {enveloped.Length:N0} bytes.");
        result.EnvelopedData = enveloped;

        // 7. Decrypt
        byte[] decrypted;
        try
        {
            using var kemKey = PqcKeyPair.ReadKemKey(encryptionRow.EncryptedPfxBytes, encryptionRow.PfxPassword ?? string.Empty);
            decrypted = KemEnvelopedData.Decrypt(enveloped, encryptionCert, kemKey.Kem);
        }
        catch (Exception ex)
        {
            return result.Fail("Decrypt (ML-KEM)", ex.Message);
        }
        if (!result.Step("Decrypt (ML-KEM)", decrypted.AsSpan().SequenceEqual(signed),
                "Decapsulated with the ML-KEM private key and unwrapped the content key."))
            return result;

        // 8. Verify
        var verified = new SignedCms();
        try
        {
            verified.Decode(decrypted);
            verified.CheckSignature(verifySignatureOnly: true);
        }
        catch (Exception ex)
        {
            return result.Fail("Verify signature", ex.Message);
        }
        var signerCert = verified.SignerInfos[0].Certificate;
        var sameSigner = signerCert?.Thumbprint == signingCert.Thumbprint
                         && verified.ContentInfo.Content.AsSpan().SequenceEqual(message);
        if (!result.Step("Verify signature", sameSigner,
                sameSigner ? "ML-DSA signature verifies; signer is the pair's signing certificate; content unchanged."
                           : "The signer or the content does not match."))
            return result;

        // 9. Sender matches the certificate (Direct Applicability Statement binding)
        var from = Encoding.UTF8.GetString(verified.ContentInfo.Content).Split("\r\n")
            .First(l => l.StartsWith("From:", StringComparison.Ordinal))[5..].Trim();
        var senderOk = identity.Contains('@')
            ? string.Equals(from, identity, StringComparison.OrdinalIgnoreCase)
            : from.EndsWith("@" + identity, StringComparison.OrdinalIgnoreCase);
        result.Step("Sender matches certificate", senderOk,
            identity.Contains('@') ? $"From {from} equals the rfc822Name." : $"From {from} is in the dNSName domain.");

        return result;
    }

    private static string? ValidateIdentifier(DirectBinding binding, string identifier)
    {
        if (string.IsNullOrEmpty(identifier))
            return "Enter the Direct address or domain.";

        if (binding == DirectBinding.Address)
            return MailAddress.TryCreate(identifier, out var address) && address.Address == identifier
                ? null
                : $"'{identifier}' is not a Direct address (name@domain).";

        return Uri.CheckHostName(identifier) == UriHostNameType.Dns && identifier.Contains('.')
            ? null
            : $"'{identifier}' is not a domain name.";
    }

    private static HashSet<string> SanValues(X509Certificate2 cert)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (cert.Extensions["2.5.29.17"] is X509SubjectAlternativeNameExtension san)
        {
            foreach (var dns in san.EnumerateDnsNames()) values.Add(dns);
            var reader = new System.Formats.Asn1.AsnReader(san.RawData, System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
            var rfc822 = new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 1);
            while (reader.HasData)
            {
                if (reader.PeekTag().HasSameClassAndValue(rfc822))
                    values.Add(reader.ReadCharacterString(System.Formats.Asn1.UniversalTagNumber.IA5String, rfc822));
                else
                    reader.ReadEncodedValue();
            }
        }
        return values;
    }

    private static X509KeyUsageFlags KeyUsage(X509Certificate2 cert) =>
        cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault()?.KeyUsages ?? X509KeyUsageFlags.None;

    private static bool HasUsage(CertificateTemplate t, X509KeyUsageFlags flag) =>
        ((X509KeyUsageFlags)t.KeyUsageFlags).HasFlag(flag);
}

public enum DirectBinding
{
    Address,
    Domain
}

public class DirectPairRequest
{
    public int TrustDomainId { get; set; }
    public int IssuingCaCertificateId { get; set; }
    public DirectBinding Binding { get; set; } = DirectBinding.Address;

    /// <summary>The Direct address (address-bound) or domain (domain-bound).</summary>
    public string Identifier { get; set; } = string.Empty;

    /// <summary>Optional; defaults to CN=&lt;identifier&gt;.</summary>
    public string? SubjectDn { get; set; }

    public int SigningTemplateId { get; set; }
    public int EncryptionTemplateId { get; set; }
    public string PfxPassword { get; set; } = string.Empty;
    public List<string> CdpUrls { get; set; } = [];
    public List<string> AiaUrls { get; set; } = [];
}

public class DirectPairResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public int? SigningCertificateId { get; set; }
    public int? EncryptionCertificateId { get; set; }

    public static DirectPairResult Failure(string error) => new() { Success = false, Error = error };
}

public class DirectRoundTripResult
{
    public List<DirectRoundTripStep> Steps { get; } = [];
    public bool Passed => Steps.Count > 0 && Steps.All(s => s.Passed);

    /// <summary>The encrypted message (DER CMS EnvelopedData) from the last run, for download.</summary>
    public byte[]? EnvelopedData { get; set; }

    internal bool Step(string name, bool passed, string detail)
    {
        Steps.Add(new DirectRoundTripStep(name, passed, detail));
        return passed;
    }

    internal DirectRoundTripResult Fail(string name, string detail)
    {
        Step(name, false, detail);
        return this;
    }
}

public record DirectRoundTripStep(string Name, bool Passed, string Detail);
