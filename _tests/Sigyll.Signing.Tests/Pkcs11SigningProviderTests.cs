#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Jobs;
using Sigyll.Common.Services.Signing;
using Sigyll.Common.ViewModels;
using Sigyll.Pkcs11;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>The PKCS #11 provider's encoding helpers; these need no token.</summary>
public class Pkcs11EncodingTests
{
    [Theory]
    [InlineData("nistP256", "1.2.840.10045.3.1.7")]
    [InlineData("nistP384", "1.3.132.0.34")]
    [InlineData(null, "1.3.132.0.34")]
    [InlineData("nistP521", "1.3.132.0.35")]
    public void CurveOid_IsDerEncoded(string? curve, string oid)
    {
        AsnDecoder.ReadObjectIdentifier(Pkcs11SigningProvider.EncodeCurveOid(curve), AsnEncodingRules.DER, out _)
            .ShouldBe(oid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void EcPoint_IsReadWrappedInAnOctetStringOrBare(bool wrapped)
    {
        using var original = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = original.ExportParameters(false).Q;
        byte[] point = [0x04, .. q.X!, .. q.Y!];
        if (wrapped)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteOctetString(point);
            point = writer.Encode();
        }

        using var imported = Pkcs11SigningProvider.ImportEcPublicKey(Pkcs11SigningProvider.EncodeCurveOid("nistP256"), point);

        imported.ExportSubjectPublicKeyInfo().ShouldBe(original.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void RawEcdsaSignature_BecomesDer_ThatVerifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var data = "to be signed"u8.ToArray();
        var raw = key.SignData(data, HashAlgorithmName.SHA384, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var der = Pkcs11SigningProvider.ConvertP1363ToDer(raw);

        key.VerifyData(data, der, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence).ShouldBeTrue();
    }

    [Theory]
    [InlineData("SoftHSM project", "SoftHSM v2", true)]
    [InlineData("Thales", "Luna K7", false)]
    public void SoftHsm_IsRecognised(string manufacturer, string model, bool expected)
    {
        Pkcs11SigningProvider.IsSoftHsm(manufacturer, model).ShouldBe(expected);
    }
}

/// <summary>Skipped unless SIGYLL_TEST_PKCS11_LIB names a SoftHSM library (CI installs one).</summary>
public sealed class SoftHsmFactAttribute : FactAttribute
{
    public const string LibraryVariable = "SIGYLL_TEST_PKCS11_LIB";

    public SoftHsmFactAttribute()
    {
        var path = Environment.GetEnvironmentVariable(LibraryVariable);
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
            Skip = $"Set {LibraryVariable} to a SoftHSM library (e.g. /usr/lib/softhsm/libsofthsm2.so) to run PKCS #11 tests.";
    }
}

/// <summary>
/// A fresh SoftHSM token for one test class, with PINs made up for the test and thrown away with it. The token is
/// initialised with its own library handle, released before the provider loads the library.
/// </summary>
public sealed class SoftHsmToken : IDisposable
{
    public string Label { get; } = "sigyll-test-" + Guid.NewGuid().ToString("N")[..8];
    public string UserPin { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    public string? LibraryPath { get; } = Environment.GetEnvironmentVariable(SoftHsmFactAttribute.LibraryVariable);

    private Pkcs11SigningProvider? _provider;

    public SoftHsmToken()
    {
        if (string.IsNullOrEmpty(LibraryPath) || !File.Exists(LibraryPath))
            return;

        NativeLibraryNames.Register();
        var soPin = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var factories = new Pkcs11InteropFactories();
        using var library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, LibraryPath, AppType.MultiThreaded);

        var free = library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => !s.GetTokenInfo().TokenFlags.TokenInitialized);
        free.InitToken(soPin, Label);

        var slot = library.GetSlotList(SlotsType.WithTokenPresent).First(s => s.GetTokenInfo().Label.Trim() == Label);
        using var session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_SO, soPin);
        session.InitPin(UserPin);
        session.Logout();
    }

    public Pkcs11SigningProvider Provider(bool hardwareProtected = false) =>
        _provider ??= new Pkcs11SigningProvider(Options.Create(new Pkcs11Options
        {
            LibraryPath = LibraryPath!,
            TokenLabel = Label,
            UserPin = UserPin,
            HardwareProtected = hardwareProtected,
        }), NullLogger<Pkcs11SigningProvider>.Instance);

    public void Dispose() => _provider?.Dispose();
}

/// <summary>Signing on a real PKCS #11 token (SoftHSM): keys stay on the token, and CAs issue and sign CRLs with them.</summary>
public class Pkcs11SoftHsmTests(SoftHsmToken token) : IClassFixture<SoftHsmToken>
{
    private readonly TestDbContextFactory _dbFactory = new();

    // HardwareProtected is claimed on purpose: SoftHSM must still be recorded as software-protected.
    private Pkcs11SigningProvider Provider => token.Provider(hardwareProtected: true);

    [SoftHsmFact]
    public async Task RsaKey_SignsOnTheToken_AndTheSignatureVerifies()
    {
        var key = await Provider.GenerateKeyAsync("RSA", 2048);
        var data = "to be signed"u8.ToArray();

        var signature = await Provider.SignDataAsync(data, HashAlgorithmName.SHA256, key);

        using var publicKey = (RSA)await Provider.GetPublicKeyAsync(key);
        publicKey.KeySize.ShouldBe(2048);
        publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();
    }

    [SoftHsmTheory]
    [InlineData("nistP256", 256, "SHA256")]
    [InlineData("nistP384", 384, "SHA384")]
    public async Task EcdsaKey_SignsOnTheToken_WithADerSignatureThatVerifies(string curve, int size, string hash)
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", size, curve);
        var data = "to be signed"u8.ToArray();
        var hashAlgorithm = new HashAlgorithmName(hash);

        var signature = await Provider.SignDataAsync(data, hashAlgorithm, key);

        using var publicKey = (ECDsa)await Provider.GetPublicKeyAsync(key);
        publicKey.KeySize.ShouldBe(size);
        publicKey.VerifyData(data, signature, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence).ShouldBeTrue();
    }

    [SoftHsmTheory]
    [InlineData("RSA", 2048, null)]
    [InlineData("ECDSA", 384, "nistP384")]
    public async Task PrivateKeys_AreMadeOnTheToken_AndCanNeverLeaveIt(string algorithm, int size, string? curve)
    {
        var key = await Provider.GenerateKeyAsync(algorithm, size, curve);

        var flags = await Provider.GetPrivateKeyFlagsAsync(key.KeyIdentifier);

        flags.Local.ShouldBeTrue("generated on the token");
        flags.Sensitive.ShouldBeTrue();
        flags.Extractable.ShouldBeFalse();
        flags.NeverExtractable.ShouldBeTrue();
    }

    [SoftHsmFact]
    public async Task SoftHsmKeys_AreRecordedAsSoftwareProtected_EvenWhenHardwareIsClaimed()
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", 384, "nistP384");

        Provider.NewKeySecurityLevel.ShouldBe(CertSecurityLevel.CloudKms);
        (await Provider.GetSecurityLevelAsync(key)).ShouldBe(CertSecurityLevel.CloudKms);
    }

    [SoftHsmFact]
    public async Task DestroyedKey_CanNoLongerSign()
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", 256, "nistP256");

        await Provider.DestroyKeyAsync(key.KeyIdentifier);

        var ex = await Should.ThrowAsync<InvalidOperationException>(() =>
            Provider.SignDataAsync([1, 2, 3], HashAlgorithmName.SHA256, key));
        ex.Message.ShouldContain("not found");
    }

    [SoftHsmFact]
    public async Task TokenCa_IssuesACertificate_AndSignsItsCrl()
    {
        var (trustDomainId, rootProfileId, leafProfileId) = await SeedAsync(requireHardwareKeys: false);
        var issuance = new CertificateIssuanceService(_dbFactory, TestOperators.Full,
            NullLogger<CertificateIssuanceService>.Instance, Provider);

        var root = await issuance.IssueCertificateAsync(new CertificateIssuanceRequest
        {
            ProfileId = rootProfileId,
            TrustDomainId = trustDomainId,
            SubjectDn = "CN=Token Root",
            CertificateName = "Token Root",
        });
        root.Success.ShouldBeTrue(root.Error);

        var leaf = await issuance.IssueCertificateAsync(new CertificateIssuanceRequest
        {
            IssuingCaCertificateId = root.EntityId,
            ProfileId = leafProfileId,
            TrustDomainId = trustDomainId,
            SubjectDn = "CN=api.example.com",
            CertificateName = "api",
            PfxPassword = "test-password",
            SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com")],
            SigningProviderOverride = "local",
        });
        leaf.Success.ShouldBeTrue(leaf.Error);

        await using (var db = _dbFactory.CreateDbContext())
        {
            var rootEntity = (await db.CaCertificates.FindAsync(root.EntityId))!;
            rootEntity.StoreProviderHint.ShouldStartWith("pkcs11:");
            rootEntity.EncryptedPfxBytes.ShouldBeNull();
            rootEntity.CertSecurityLevel.ShouldBe(CertSecurityLevel.CloudKms);

            using var rootCert = X509Certificate2.CreateFromPem(rootEntity.X509CertificatePem);
            using var leafCert = X509Certificate2.CreateFromPem((await db.IssuedCertificates.FindAsync(leaf.EntityId))!.X509CertificatePem);
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(rootCert);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(leafCert).ShouldBeTrue(string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation)));
        }

        var crls = new CrlGenerationService(_dbFactory, TestOperators.Full, NullLogger<CrlGenerationService>.Instance, Provider);
        var crl = await crls.GenerateCrlAsync(root.EntityId!.Value);
        crl.IsSuccess.ShouldBeTrue(crl.Error);
        await using var check = _dbFactory.CreateDbContext();
        (await check.Crls.FindAsync(crl.CrlEntityId))!.SignatureValid.ShouldBeTrue();
    }

    [SoftHsmFact]
    public async Task SoftHsmRoot_IsRefused_WhereCaKeysMustBeInAnHsm()
    {
        var (trustDomainId, rootProfileId, _) = await SeedAsync(requireHardwareKeys: true);
        var issuance = new CertificateIssuanceService(_dbFactory, TestOperators.Full,
            NullLogger<CertificateIssuanceService>.Instance, Provider);

        var root = await issuance.IssueCertificateAsync(new CertificateIssuanceRequest
        {
            ProfileId = rootProfileId,
            TrustDomainId = trustDomainId,
            SubjectDn = "CN=Token Root",
            CertificateName = "Token Root",
        });

        root.Success.ShouldBeFalse();
        root.Error!.ShouldContain("requires CA keys held in an HSM");
    }

    private async Task<(int TrustDomainId, int RootProfileId, int LeafProfileId)> SeedAsync(bool requireHardwareKeys)
    {
        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Token TD", Enabled = true, RequireHardwareKeys = requireHardwareKeys };
        db.TrustDomains.Add(trustDomain);
        var root = new CertificateProfile
        {
            Name = "Root",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "ECDSA",
            EcdsaCurve = "nistP384",
            KeySize = 384,
            ValidityDays = 3650,
            KeyUsageFlags = (int)(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign),
            IsBasicConstraintsCa = true,
            HashAlgorithm = "SHA384",
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
        return (trustDomain.Id, root.Id, leaf.Id);
    }
}

/// <summary>Theory counterpart of <see cref="SoftHsmFactAttribute"/>.</summary>
public sealed class SoftHsmTheoryAttribute : TheoryAttribute
{
    public SoftHsmTheoryAttribute()
    {
        Skip = new SoftHsmFactAttribute().Skip;
    }
}
