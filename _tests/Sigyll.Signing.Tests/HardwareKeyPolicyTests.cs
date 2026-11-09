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
using System.Security.Cryptography.X509Certificates;
using Google.Cloud.Kms.V1;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Audit;
using Sigyll.Common.Services.Signing;
using Sigyll.Common.ViewModels;
using Sigyll.Gcp;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>
/// A trust domain can require its CA keys to be held in an HSM; remote keys are recorded with the protection the key
/// service reports.
/// </summary>
public class HardwareKeyPolicyTests
{
    private readonly TestDbContextFactory _dbFactory = new();

    [Fact]
    public async Task RootCa_InHsmOnlyDomain_WithHsmKey_IsIssuedAndRecordedAsCloudHsm()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);

        var result = await Service(new FakeKeyService(CertSecurityLevel.CloudHsm)).IssueCertificateAsync(Root(seed));

        result.Success.ShouldBeTrue(result.Error);
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.FindAsync(result.EntityId))!.CertSecurityLevel.ShouldBe(CertSecurityLevel.CloudHsm);
    }

    [Fact]
    public async Task RootCa_InHsmOnlyDomain_WithP12Key_IsRefused()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);
        var request = Root(seed);
        request.SigningProviderOverride = "local";
        request.PfxPassword = "test-password";

        var result = await Service(new FakeKeyService(CertSecurityLevel.CloudHsm)).IssueCertificateAsync(request);

        result.Success.ShouldBeFalse();
        result.Error!.ShouldContain("requires CA keys held in an HSM");
        result.Error.ShouldContain("P12 file");
    }

    [Fact]
    public async Task RootCa_InHsmOnlyDomain_WithProviderConfiguredForSoftwareKeys_IsRefusedBeforeMakingAKey()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);
        var keyService = new FakeKeyService(CertSecurityLevel.CloudKms);

        var result = await Service(keyService).IssueCertificateAsync(Root(seed));

        result.Success.ShouldBeFalse();
        result.Error!.ShouldContain("protects it in software");
        keyService.KeysMade.ShouldBe(0);
    }

    [Fact]
    public async Task RootCa_InHsmOnlyDomain_WhenTheKeyServiceMakesASoftwareKey_IsRefused()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);
        var keyService = new FakeKeyService(CertSecurityLevel.CloudHsm) { Reports = CertSecurityLevel.CloudKms };

        var result = await Service(keyService).IssueCertificateAsync(Root(seed));

        result.Success.ShouldBeFalse();
        result.Error!.ShouldContain("was not used");
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.CountAsync()).ShouldBe(0);
    }

    [Fact]
    public async Task EndEntity_FromAnHsmCa_InHsmOnlyDomain_IsIssued()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);
        var service = Service(new FakeKeyService(CertSecurityLevel.CloudHsm));
        var root = await service.IssueCertificateAsync(Root(seed));
        root.Success.ShouldBeTrue(root.Error);

        // The end-entity key is a P12 file; only CA keys must be in an HSM.
        var leaf = await service.IssueCertificateAsync(Leaf(seed, root.EntityId!.Value, local: true));

        leaf.Error.ShouldBeNull();
        leaf.Success.ShouldBeTrue();
        await using var db = _dbFactory.CreateDbContext();
        (await db.IssuedCertificates.FindAsync(leaf.EntityId))!.CertSecurityLevel.ShouldBe(CertSecurityLevel.Software);
    }

    [Fact]
    public async Task EndEntity_FromASoftwareCa_InHsmOnlyDomain_IsRefused_FromAKeyOrACsr()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);
        var caId = await SeedSoftwareCaAsync(seed.TrustDomainId);
        var service = Service(new LocalSigningProvider());

        var leaf = await service.IssueCertificateAsync(Leaf(seed, caId, local: true));
        leaf.Success.ShouldBeFalse();
        leaf.Error!.ShouldContain("issuing CA 'Software CA' has its key in a P12 file");

        using var key = RSA.Create(2048);
        var fromCsr = await service.IssueCertificateFromCsrAsync(new CsrIssuanceRequest
        {
            IssuingCaCertificateId = caId,
            ProfileId = seed.LeafProfileId,
            TrustDomainId = seed.TrustDomainId,
            CsrPem = new CertificateRequest("CN=api.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSigningRequestPem(),
            SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com")],
        });
        fromCsr.Success.ShouldBeFalse();
        fromCsr.Error!.ShouldContain("requires CA keys held in an HSM");
    }

    [Fact]
    public async Task EndEntity_FromASoftwareCa_InAnOrdinaryDomain_IsIssued()
    {
        var seed = await SeedAsync(requireHardwareKeys: false);
        var caId = await SeedSoftwareCaAsync(seed.TrustDomainId);

        var leaf = await Service(new LocalSigningProvider()).IssueCertificateAsync(Leaf(seed, caId, local: true));

        leaf.Success.ShouldBeTrue(leaf.Error);
    }

    [Fact]
    public async Task Resign_InHsmOnlyDomain_IsRefused()
    {
        var seed = await SeedAsync(requireHardwareKeys: true);
        var caId = await SeedSoftwareCaAsync(seed.TrustDomainId);

        var result = await Service(new LocalSigningProvider()).ResignCertificateAsync(new CertificateResignRequest
        {
            ExistingCertificateId = caId,
            EntityType = "CaCertificate",
            PfxPassword = "test-password",
        });

        result.Success.ShouldBeFalse();
        result.Error!.ShouldContain("Re-signing");
    }

    [Fact]
    public async Task RemoteKey_InAnOrdinaryDomain_IsRecordedAsTheKeyServiceReports()
    {
        var seed = await SeedAsync(requireHardwareKeys: false);

        var result = await Service(new FakeKeyService(CertSecurityLevel.CloudKms)).IssueCertificateAsync(Root(seed));

        result.Success.ShouldBeTrue(result.Error);
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.FindAsync(result.EntityId))!.CertSecurityLevel.ShouldBe(CertSecurityLevel.CloudKms);
    }

    [Fact]
    public async Task SettingTheRule_NeedsAnAdmin_AndIsAudited()
    {
        var seed = await SeedAsync(requireHardwareKeys: false);

        var asOperator = new TrustDomainService(_dbFactory, TestOperators.With(Permission.View, Permission.Operate),
            NullLogger<TrustDomainService>.Instance);
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => asOperator.SetRequireHardwareKeysAsync(seed.TrustDomainId, true));

        var asAdmin = new TrustDomainService(_dbFactory, TestOperators.Full, NullLogger<TrustDomainService>.Instance);
        await asAdmin.SetRequireHardwareKeysAsync(seed.TrustDomainId, true);

        await using var db = _dbFactory.CreateDbContext();
        (await db.TrustDomains.FindAsync(seed.TrustDomainId))!.RequireHardwareKeys.ShouldBeTrue();
        (await db.AuditEvents.SingleAsync(e => e.Action == AuditActions.TrustDomainKeyPolicyChanged))
            .Detail.ShouldBe("CA keys must now be held in an HSM.");

        var domains = await asAdmin.GetAllAsync();
        domains.Single().RequireHardwareKeys.ShouldBeTrue();
    }

    [Fact]
    public async Task TrustDomainList_CountsCasWithKeysOutsideAnHsm()
    {
        var seed = await SeedAsync(requireHardwareKeys: false);
        await SeedSoftwareCaAsync(seed.TrustDomainId);
        var root = await Service(new FakeKeyService(CertSecurityLevel.CloudHsm)).IssueCertificateAsync(Root(seed));
        root.Success.ShouldBeTrue(root.Error);

        var domains = await new TrustDomainService(_dbFactory, TestOperators.Full, NullLogger<TrustDomainService>.Instance)
            .GetAllAsync();

        domains.Single().NonHardwareCaKeyCount.ShouldBe(1);
    }

    [Theory]
    [InlineData("HSM", CertSecurityLevel.CloudHsm)]
    [InlineData(null, CertSecurityLevel.CloudHsm)]
    [InlineData("software", CertSecurityLevel.CloudKms)]
    public void GcpProtectionLevel_DefaultsToHsm(string? configured, CertSecurityLevel expected)
    {
        GcpKmsSigningProvider.ToSecurityLevel(GcpKmsSigningProvider.ParseProtectionLevel(configured)).ShouldBe(expected);
    }

    [Fact]
    public void GcpProtectionLevel_RejectsUnknownValues_AndTreatsExternalKeysAsNotHardware()
    {
        Should.Throw<InvalidOperationException>(() => GcpKmsSigningProvider.ParseProtectionLevel("EXTERNAL"));
        GcpKmsSigningProvider.ToSecurityLevel(ProtectionLevel.External).IsHardware().ShouldBeFalse();
    }

    // --- helpers ---

    private sealed record Seed(int TrustDomainId, int RootProfileId, int LeafProfileId);

    private CertificateIssuanceService Service(ISigningProvider provider) =>
        new(_dbFactory, TestOperators.Full, NullLogger<CertificateIssuanceService>.Instance, provider);

    private static CertificateIssuanceRequest Root(Seed seed) => new()
    {
        ProfileId = seed.RootProfileId,
        TrustDomainId = seed.TrustDomainId,
        SubjectDn = "CN=Test Root",
        CertificateName = "Test Root",
    };

    private static CertificateIssuanceRequest Leaf(Seed seed, int caId, bool local) => new()
    {
        IssuingCaCertificateId = caId,
        ProfileId = seed.LeafProfileId,
        TrustDomainId = seed.TrustDomainId,
        SubjectDn = "CN=api.example.com",
        CertificateName = "api",
        PfxPassword = "test-password",
        SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com")],
        SigningProviderOverride = local ? "local" : null,
    };

    private async Task<Seed> SeedAsync(bool requireHardwareKeys)
    {
        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Test TD", Enabled = true, RequireHardwareKeys = requireHardwareKeys };
        db.TrustDomains.Add(trustDomain);

        var root = new CertificateProfile
        {
            Name = "Root",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 3650,
            KeyUsageFlags = (int)(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign),
            IsBasicConstraintsCa = true,
            HashAlgorithm = "SHA256",
        };
        var leaf = new CertificateProfile
        {
            Name = "Server",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            HashAlgorithm = "SHA256",
        };
        db.CertificateProfiles.AddRange(root, leaf);
        await db.SaveChangesAsync();
        return new Seed(trustDomain.Id, root.Id, leaf.Id);
    }

    private async Task<int> SeedSoftwareCaAsync(int trustDomainId)
    {
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Software CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        await using var db = _dbFactory.CreateDbContext();
        var ca = new CaCertificate
        {
            TrustDomainId = trustDomainId,
            Name = "Software CA",
            Subject = "CN=Software CA",
            X509CertificatePem = caCert.ExportCertificatePem(),
            EncryptedPfxBytes = caCert.Export(X509ContentType.Pkcs12, "test-password"),
            PfxPassword = "test-password",
            Thumbprint = caCert.Thumbprint,
            SerialNumber = caCert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter,
            CertSecurityLevel = CertSecurityLevel.Software,
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();
        return ca.Id;
    }

    /// <summary>
    /// A remote key service that keeps its keys in memory and reports a chosen protection level. It answers to
    /// "gcp-kms" so CAs it creates can act as issuers, as Cloud KMS keys do.
    /// </summary>
    private sealed class FakeKeyService(CertSecurityLevel configured) : ISigningProvider, IKeyProtectionReporter
    {
        private readonly LocalSigningProvider _keys = new();

        public CertSecurityLevel Reports { get; init; } = configured;
        public int KeysMade { get; private set; }

        public string ProviderName => "gcp-kms";
        public CertSecurityLevel NewKeySecurityLevel => configured;

        public Task<CertSecurityLevel> GetSecurityLevelAsync(SigningKeyReference keyRef, CancellationToken ct = default) =>
            Task.FromResult(Reports);

        public async Task<SigningKeyReference> GenerateKeyAsync(string keyAlgorithm, int keySize, string? ecdsaCurve = null,
            CancellationToken ct = default)
        {
            KeysMade++;
            var key = await _keys.GenerateKeyAsync(keyAlgorithm, keySize, ecdsaCurve, ct);
            return key with { Provider = ProviderName };
        }

        public Task<byte[]> SignDataAsync(byte[] data, HashAlgorithmName hashAlgorithm, SigningKeyReference keyRef,
            CancellationToken ct = default) => _keys.SignDataAsync(data, hashAlgorithm, keyRef, ct);

        // A fresh public-key object each call, as a real key service returns; callers dispose it.
        public async Task<AsymmetricAlgorithm> GetPublicKeyAsync(SigningKeyReference keyRef, CancellationToken ct = default)
        {
            var stored = await _keys.GetPublicKeyAsync(keyRef, ct);
            var spki = stored.ExportSubjectPublicKeyInfo();
            AsymmetricAlgorithm copy = stored is ECDsa ? ECDsa.Create() : RSA.Create();
            copy.ImportSubjectPublicKeyInfo(spki, out _);
            return copy;
        }

        public Task<RawPublicKey> GetRawPublicKeyAsync(SigningKeyReference keyRef, CancellationToken ct = default) =>
            _keys.GetRawPublicKeyAsync(keyRef, ct);
    }
}
