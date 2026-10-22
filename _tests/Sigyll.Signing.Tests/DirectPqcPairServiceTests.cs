#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Pqc;
using Sigyll.Common.ViewModels;

namespace Sigyll.Signing.Tests;

public class DirectPqcPairServiceTests
{
    private const string Password = "pair-test-pw";
    private readonly TestDbContextFactory _dbFactory = new();
    private readonly CertificateIssuanceService _issuance;
    private readonly DirectPqcPairService _service;

    public DirectPqcPairServiceTests()
    {
        _issuance = new CertificateIssuanceService(_dbFactory, TestOperators.Full, NullLogger<CertificateIssuanceService>.Instance);
        var chain = new ChainValidationService(_dbFactory, TestOperators.Full, Substitute.For<IHttpClientFactory>(),
            NullLogger<ChainValidationService>.Instance);
        _service = new DirectPqcPairService(_dbFactory, TestOperators.Full, _issuance, chain, NullLogger<DirectPqcPairService>.Instance);
    }

    [Fact]
    public async Task MlKemCertificate_IssuesWithAnAes256Pfx()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        var seed = await SeedAsync();

        var result = await _issuance.IssueCertificateAsync(new CertificateIssuanceRequest
        {
            IssuingCaCertificateId = seed.CaId,
            ProfileId = seed.EncryptionProfileId,
            TrustDomainId = seed.TrustDomainId,
            SubjectDn = "CN=kem.example.com",
            SubjectAltNames = [new SanEntry(SanType.Email, "kem@example.com")],
            PfxPassword = Password,
        });

        result.Success.ShouldBeTrue(result.Error);
        await using var db = _dbFactory.CreateDbContext();
        var row = await db.IssuedCertificates.FindAsync(result.EntityId);
        row!.KeyAlgorithm.ShouldBe("ML-KEM-1024");
        AssertModernPfx(row.EncryptedPfxBytes!, Password);
        using var key = PqcKeyPair.ReadKemKey(row.EncryptedPfxBytes!, Password);
        key.AlgorithmId.ShouldBe("ML-KEM-1024");
    }

    [Fact]
    public async Task IssuePair_LinksTheCertificates_AndTheRoundTripPasses()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        var seed = await SeedAsync();

        var pair = await _service.IssuePairAsync(Request(seed, DirectBinding.Address, "alice@direct.example.org"));

        pair.Success.ShouldBeTrue(pair.Error);
        await using (var db = _dbFactory.CreateDbContext())
        {
            var signing = await db.IssuedCertificates.FindAsync(pair.SigningCertificateId);
            var encryption = await db.IssuedCertificates.FindAsync(pair.EncryptionCertificateId);
            using var signingCert = X509Certificate2.CreateFromPem(signing!.X509CertificatePem);
            using var encryptionCert = X509Certificate2.CreateFromPem(encryption!.X509CertificatePem);

            CertificateExtensionHelpers.IsRelatedTo(encryptionCert, signingCert.RawData).ShouldBeTrue();
            CertificateExtensionHelpers.IsRelatedTo(signingCert, encryptionCert.RawData).ShouldBeFalse();
            encryptionCert.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages
                .ShouldBe(X509KeyUsageFlags.KeyEncipherment);
            signing.SubjectAltNames.ShouldBe("Email:alice@direct.example.org");
            encryption.SubjectAltNames.ShouldBe("Email:alice@direct.example.org");
        }

        var roundTrip = await _service.RunRoundTripAsync(pair.SigningCertificateId!.Value, pair.EncryptionCertificateId!.Value);

        roundTrip.Passed.ShouldBeTrue(string.Join("\n", roundTrip.Steps.Select(s => $"{s.Name}: {s.Passed} {s.Detail}")));
        roundTrip.Steps.Select(s => s.Name).ShouldBe([
            "Bound to one identity", "Key usage split", "RFC 9763 link", "Chain (signing)", "Chain (encryption)",
            "Sign (ML-DSA)", "Encrypt (ML-KEM)", "Decrypt (ML-KEM)", "Verify signature", "Sender matches certificate"]);
    }

    [Fact]
    public async Task IssuePair_DomainBound_UsesDnsName()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        var seed = await SeedAsync();

        var pair = await _service.IssuePairAsync(Request(seed, DirectBinding.Domain, "direct.example.org"));

        pair.Success.ShouldBeTrue(pair.Error);
        var roundTrip = await _service.RunRoundTripAsync(pair.SigningCertificateId!.Value, pair.EncryptionCertificateId!.Value);
        roundTrip.Passed.ShouldBeTrue(string.Join("\n", roundTrip.Steps.Select(s => $"{s.Name}: {s.Detail}")));
    }

    [Fact]
    public async Task RoundTrip_FailsWhenTheCertificatesBelongToDifferentAddresses()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        var seed = await SeedAsync();
        var alice = await _service.IssuePairAsync(Request(seed, DirectBinding.Address, "alice@direct.example.org"));
        var bob = await _service.IssuePairAsync(Request(seed, DirectBinding.Address, "bob@direct.example.org"));

        var mixed = await _service.RunRoundTripAsync(alice.SigningCertificateId!.Value, bob.EncryptionCertificateId!.Value);

        mixed.Passed.ShouldBeFalse();
        mixed.Steps.Last().Name.ShouldBe("Bound to one identity");
    }

    [Fact]
    public async Task IssuePair_RejectsWrongProfilesAndBadAddresses()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        var seed = await SeedAsync();

        var swapped = Request(seed, DirectBinding.Address, "alice@direct.example.org");
        (swapped.SigningProfileId, swapped.EncryptionProfileId) = (swapped.EncryptionProfileId, swapped.SigningProfileId);
        (await _service.IssuePairAsync(swapped)).Error!.ShouldContain("signing profile");

        (await _service.IssuePairAsync(Request(seed, DirectBinding.Address, "not-an-address"))).Error!
            .ShouldContain("not a Direct address");

        await using var db = _dbFactory.CreateDbContext();
        db.IssuedCertificates.Count().ShouldBe(0);
    }

    [Fact]
    public async Task Rekey_ReplacesBothHalvesAsALinkedPair()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        var seed = await SeedAsync();
        var first = await _service.IssuePairAsync(Request(seed, DirectBinding.Address, "alice@direct.example.org"));
        first.Success.ShouldBeTrue(first.Error);

        // Either half finds the other through the RFC 9763 hash.
        var pair = await _service.FindPairAsync(first.EncryptionCertificateId!.Value);
        pair.ShouldNotBeNull();
        (await _service.FindPairAsync(first.SigningCertificateId!.Value)).ShouldBe(pair);
        pair!.Linked.ShouldBeTrue();
        pair.Binding.ShouldBe(DirectBinding.Address);
        pair.Identifier.ShouldBe("alice@direct.example.org");
        pair.SigningCertificateId.ShouldBe(first.SigningCertificateId!.Value);
        pair.EncryptionCertificateId.ShouldBe(first.EncryptionCertificateId!.Value);

        var rekey = Request(seed, DirectBinding.Address, "alice@direct.example.org");
        rekey.RenewalOfSigningId = pair.SigningCertificateId;
        rekey.RenewalOfEncryptionId = pair.EncryptionCertificateId;
        rekey.SigningName = "alice@direct.example.org (signing) (2)";
        rekey.EncryptionName = "alice@direct.example.org (encryption) (2)";
        var second = await _service.IssuePairAsync(rekey);
        second.Success.ShouldBeTrue(second.Error);

        await using (var db = _dbFactory.CreateDbContext())
        {
            var oldSigning = await db.IssuedCertificates.FindAsync(first.SigningCertificateId);
            var signing = await db.IssuedCertificates.FindAsync(second.SigningCertificateId);
            var encryption = await db.IssuedCertificates.FindAsync(second.EncryptionCertificateId);
            signing!.RenewalOfId.ShouldBe(first.SigningCertificateId);
            encryption!.RenewalOfId.ShouldBe(first.EncryptionCertificateId);
            signing.Version.ShouldBe(2);
            encryption.Version.ShouldBe(2);
            signing.Name.ShouldBe("alice@direct.example.org (signing) (2)");

            using var oldSigningCert = X509Certificate2.CreateFromPem(oldSigning!.X509CertificatePem);
            using var signingCert = X509Certificate2.CreateFromPem(signing.X509CertificatePem);
            using var encryptionCert = X509Certificate2.CreateFromPem(encryption.X509CertificatePem);
            CertificateExtensionHelpers.IsRelatedTo(encryptionCert, signingCert.RawData).ShouldBeTrue();
            CertificateExtensionHelpers.IsRelatedTo(encryptionCert, oldSigningCert.RawData).ShouldBeFalse();
        }

        // Each new half resolves to its new partner, not the old one.
        (await _service.FindPairAsync(second.SigningCertificateId!.Value))!.EncryptionCertificateId.ShouldBe(second.EncryptionCertificateId!.Value);
        (await _service.FindPairAsync(second.EncryptionCertificateId!.Value))!.SigningCertificateId.ShouldBe(second.SigningCertificateId!.Value);
        (await _service.RunRoundTripAsync(second.SigningCertificateId!.Value, second.EncryptionCertificateId!.Value)).Passed.ShouldBeTrue();

        // A half re-keyed on its own carries no link; it still finds the newest signing certificate for its identity.
        var lone = await _issuance.IssueCertificateAsync(new CertificateIssuanceRequest
        {
            IssuingCaCertificateId = seed.CaId, ProfileId = seed.EncryptionProfileId, TrustDomainId = seed.TrustDomainId,
            SubjectDn = "CN=alice@direct.example.org", CertificateName = "lone encryption",
            SubjectAltNames = [new SanEntry(SanType.Email, "alice@direct.example.org")],
            PfxPassword = Password, SigningProviderOverride = "local",
        });
        lone.Success.ShouldBeTrue(lone.Error);
        var fallback = await _service.FindPairAsync(lone.EntityId!.Value);
        fallback.ShouldNotBeNull();
        fallback!.Linked.ShouldBeFalse();
        fallback.SigningCertificateId.ShouldBe(second.SigningCertificateId!.Value);
    }

    [Fact]
    public void KemEnvelopedData_RejectsTheWrongRecipient()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported) return;
        using var ca = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var caCert = new CertificateRequest("CN=CA", ca).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var (aliceCert, aliceKey) = KemLeaf(ca, caCert, "CN=alice");
        var (bobCert, bobKey) = KemLeaf(ca, caCert, "CN=bob");

        var envelope = KemEnvelopedData.Encrypt([1, 2, 3], aliceCert);

        KemEnvelopedData.Decrypt(envelope, aliceCert, aliceKey).ShouldBe(new byte[] { 1, 2, 3 });
        Should.Throw<CryptographicException>(() => KemEnvelopedData.Decrypt(envelope, bobCert, bobKey));
    }

    [Fact]
    public void Pkcs12Writer_WritesAes256_AndRewrapsLegacy3DesFiles()
    {
        using var rsa = RSA.Create(2048);
        using var cert = new CertificateRequest("CN=legacy", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));

        var modern = Pkcs12Writer.Write(cert, "pw");
        AssertModernPfx(modern, "pw");
        using (var loaded = X509CertificateLoader.LoadPkcs12(modern, "pw", X509KeyStorageFlags.EphemeralKeySet))
            loaded.GetRSAPrivateKey().ShouldNotBeNull();

#pragma warning disable SYSLIB0057
        var legacy = cert.Export(X509ContentType.Pkcs12, "old"); // 3DES / SHA-1
#pragma warning restore SYSLIB0057
        var rewrapped = Pkcs12Writer.Rewrap(legacy, "old", "new", [cert]);
        AssertModernPfx(rewrapped, "new");
        using var reloaded = X509CertificateLoader.LoadPkcs12(rewrapped, "new", X509KeyStorageFlags.EphemeralKeySet);
        reloaded.Thumbprint.ShouldBe(cert.Thumbprint);
        reloaded.GetRSAPrivateKey().ShouldNotBeNull();

        Should.Throw<CryptographicException>(() => Pkcs12Writer.Rewrap(legacy, "wrong"));
    }

    private static void AssertModernPfx(byte[] pfx, string password)
    {
        var info = Pkcs12Info.Decode(pfx, out _);
        info.IntegrityMode.ShouldBe(Pkcs12IntegrityMode.Password);
        info.VerifyMac(password).ShouldBeTrue();

        // MacData.mac.digestAlgorithm must be SHA-256
        var mac = new System.Formats.Asn1.AsnReader(pfx, System.Formats.Asn1.AsnEncodingRules.BER).ReadSequence();
        mac.ReadInteger();
        mac.ReadEncodedValue();
        mac.ReadSequence().ReadSequence().ReadSequence().ReadObjectIdentifier().ShouldBe("2.16.840.1.101.3.4.2.1");

        foreach (var safe in info.AuthenticatedSafe)
        {
            if (safe.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
                safe.Decrypt(password);
            foreach (var bag in safe.GetBags().OfType<Pkcs12ShroudedKeyBag>())
            {
                // EncryptedPrivateKeyInfo.encryptionAlgorithm = PBES2 { PBKDF2-HMAC-SHA256, AES-256-CBC }
                var epki = new System.Formats.Asn1.AsnReader(bag.EncryptedPkcs8PrivateKey, System.Formats.Asn1.AsnEncodingRules.BER).ReadSequence();
                var alg = epki.ReadSequence();
                alg.ReadObjectIdentifier().ShouldBe("1.2.840.113549.1.5.13");
                var pbes2 = alg.ReadSequence();
                pbes2.ReadEncodedValue();
                pbes2.ReadSequence().ReadObjectIdentifier().ShouldBe("2.16.840.1.101.3.4.1.42");
            }
        }
    }

    private static (X509Certificate2 Cert, MLKem Key) KemLeaf(MLDsa ca, X509Certificate2 caCert, string subject)
    {
        var key = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
        var cert = new CertificateRequest(new X500DistinguishedName(subject), publicKey, HashAlgorithmName.SHA256)
            .Create(caCert.SubjectName, X509SignatureGenerator.CreateForMLDsa(ca),
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(8));
        return (cert, key);
    }

    private static DirectPairRequest Request(Seed seed, DirectBinding binding, string identifier) => new()
    {
        TrustDomainId = seed.TrustDomainId,
        IssuingCaCertificateId = seed.CaId,
        Binding = binding,
        Identifier = identifier,
        SigningProfileId = seed.SigningProfileId,
        EncryptionProfileId = seed.EncryptionProfileId,
        PfxPassword = Password,
    };

    private sealed record Seed(int TrustDomainId, int CaId, int SigningProfileId, int EncryptionProfileId);

    private async Task<Seed> SeedAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var domain = new TrustDomain { Name = "PQC Direct", Enabled = true };
        db.TrustDomains.Add(domain);
        var rootProfile = Profile("Root", CertificateType.RootCa, "ML-DSA-87", 87,
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, ca: true);
        var signing = Profile("Direct Signing", CertificateType.EndEntityClient, "ML-DSA-87", 87, X509KeyUsageFlags.DigitalSignature);
        var encryption = Profile("Direct Encryption", CertificateType.EndEntityClient, "ML-KEM-1024", 1024, X509KeyUsageFlags.KeyEncipherment);
        db.CertificateProfiles.AddRange(rootProfile, signing, encryption);
        await db.SaveChangesAsync();

        var root = await _issuance.IssueCertificateAsync(new CertificateIssuanceRequest
        {
            ProfileId = rootProfile.Id,
            TrustDomainId = domain.Id,
            SubjectDn = "CN=PQC Direct Root",
            PfxPassword = Password,
        });
        root.Success.ShouldBeTrue(root.Error);
        AssertModernPfx((await db.CaCertificates.FindAsync(root.EntityId))!.EncryptedPfxBytes!, Password);

        var crl = await new Sigyll.Common.Services.Jobs.CrlGenerationService(_dbFactory, TestOperators.Full, NullLogger<Sigyll.Common.Services.Jobs.CrlGenerationService>.Instance, new Sigyll.Common.Services.Signing.LocalSigningProvider())
            .GenerateCrlAsync(root.EntityId!.Value);
        crl.IsSuccess.ShouldBeTrue(crl.Error);

        return new Seed(domain.Id, root.EntityId!.Value, signing.Id, encryption.Id);
    }

    private static CertificateProfile Profile(string name, CertificateType type, string algorithm, int size,
        X509KeyUsageFlags usage, bool ca = false) => new()
    {
        Name = name,
        CertificateType = type,
        KeyAlgorithm = algorithm,
        KeySize = size,
        ValidityDays = 365,
        KeyUsageFlags = (int)usage,
        IsKeyUsageCritical = true,
        IsBasicConstraintsCa = ca,
        ExtendedKeyUsageOids = ca ? null : "1.3.6.1.5.5.7.3.4",
        HashAlgorithm = "Pure",
    };
}
