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
using Shouldly;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;

namespace Sigyll.Signing.Tests;

public class CertificateImportServiceTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();

    private CertificateImportService CreateService() =>
        new(_dbFactory, NullLogger<CertificateImportService>.Instance);

    [Fact]
    public async Task ImportParsed_RootCa_CreatesEntity()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        var parsed = CreateParsedRootCa();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(parsed, trustDomainId);

        result.Success.ShouldBeTrue();
        result.AlreadyExists.ShouldBeFalse();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FirstOrDefaultAsync(c => c.TrustDomainId == trustDomainId);
        ca.ShouldNotBeNull();
        ca!.Subject.ShouldContain("Root");
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_EndEntity_WithCa_CreatesIssuedCert()
    {
        var (trustDomainId, caId) = await SeedTrustDomainWithCaAsync();
        var parsed = CreateParsedEndEntity();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(
            parsed, trustDomainId, issuingCaId: caId);

        result.Success.ShouldBeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var issued = await db.IssuedCertificates.FirstOrDefaultAsync();
        issued.ShouldNotBeNull();
        issued!.IssuingCaCertificateId.ShouldBe(caId);
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_EndEntity_NoCaMatch_ReturnsNeedsCaSelection()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        var parsed = CreateParsedEndEntity();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(parsed, trustDomainId);

        result.NeedsCaSelection.ShouldBeTrue();
        result.Success.ShouldBeFalse();
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_DuplicateThumbprint_ReturnsMerged()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        var service = CreateService();

        var parsed1 = CreateParsedRootCa();
        var result1 = await service.ImportParsedCertificateAsync(parsed1, trustDomainId);
        result1.Success.ShouldBeTrue();

        // Import the same cert again — should merge, not duplicate
        var parsed2 = CreateParsedRootCaFrom(parsed1.Certificate);
        var result2 = await service.ImportParsedCertificateAsync(parsed2, trustDomainId);

        result2.Success.ShouldBeTrue();
        result2.AlreadyExists.ShouldBeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var count = await db.CaCertificates.CountAsync(c => c.TrustDomainId == trustDomainId);
        count.ShouldBe(1);

        parsed1.Certificate.Dispose();
        parsed2.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_DuplicateWithPfx_MergesPfxBytes()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        var service = CreateService();

        var parsed1 = CreateParsedRootCa(hasPrivateKey: false);
        await service.ImportParsedCertificateAsync(parsed1, trustDomainId);

        // Import same cert again but with PFX bytes this time
        var pfxBytes = parsed1.Certificate.Export(X509ContentType.Pkcs12, "pass");
        var parsed2 = CreateParsedRootCaFrom(parsed1.Certificate, hasPrivateKey: true);
        var result = await service.ImportParsedCertificateAsync(
            parsed2, trustDomainId, password: "pass", rawFileOverride: pfxBytes);

        result.Success.ShouldBeTrue();
        result.AlreadyExists.ShouldBeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var ca = await db.CaCertificates.FirstAsync(c => c.Thumbprint == parsed1.Certificate.Thumbprint);
        ca.EncryptedPfxBytes.ShouldNotBeNull();
        ca.PfxPassword.ShouldBe("pass");

        parsed1.Certificate.Dispose();
        parsed2.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_CustomName_UsesProvidedName()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        var parsed = CreateParsedRootCa();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(
            parsed, trustDomainId, name: "My Custom CA");

        result.ImportedName.ShouldBe("My Custom CA");
        parsed.Certificate.Dispose();
    }

    [Fact]
    public async Task ImportParsed_IntermediateCa_WithExplicitParent_SetsParentId()
    {
        var (trustDomainId, caId) = await SeedTrustDomainWithCaAsync();
        var parsed = CreateParsedIntermediateCa();
        var service = CreateService();

        var result = await service.ImportParsedCertificateAsync(
            parsed, trustDomainId, issuingCaId: caId);

        result.Success.ShouldBeTrue();

        await using var db = _dbFactory.CreateDbContext();
        var intermediate = await db.CaCertificates
            .FirstOrDefaultAsync(c => c.Thumbprint == parsed.Certificate.Thumbprint);
        intermediate.ShouldNotBeNull();
        intermediate!.ParentId.ShouldBe(caId);
        parsed.Certificate.Dispose();
    }

    /// <summary>
    /// CSR round trip: the operator generated a CSR reusing an existing certificate's key, the
    /// external CA returned a new certificate (public only). Importing that .cer must pair it with
    /// the stored private key and record it as the successor of the original.
    /// </summary>
    [Fact]
    public async Task ImportParsed_PublicOnlyCertWithKnownPublicKey_PairsStoredPrivateKey()
    {
        var (trustDomainId, caId) = await SeedTrustDomainWithCaAsync();
        var service = CreateService();

        // Original certificate, imported earlier with its private key
        var rsa = RSA.Create(2048);
        var originalReq = new CertificateRequest("CN=Renewing Client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var original = originalReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddDays(10));
        var originalParsed = new ParsedCertificate
        {
            Certificate = X509CertificateLoader.LoadCertificate(original.RawData),
            RawFileBytes = original.Export(X509ContentType.Pkcs12, "orig-pw"),
            FileName = "renewing-client.pfx",
            DetectedRole = DetectedCertRole.EndEntity,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = true
        };
        (await service.ImportParsedCertificateAsync(originalParsed, trustDomainId,
            name: "renewing-client", password: "orig-pw", issuingCaId: caId)).Success.ShouldBeTrue();

        // Renewal returned by the external CA: same public key, new serial/validity, no private key
        var renewalReq = new CertificateRequest("CN=Renewing Client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var renewalSigned = renewalReq.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var renewalPublic = X509CertificateLoader.LoadCertificate(renewalSigned.RawData);
        var renewalParsed = new ParsedCertificate
        {
            Certificate = renewalPublic,
            RawFileBytes = renewalPublic.RawData,
            FileName = "renewing-client-2026.cer",
            DetectedRole = DetectedCertRole.EndEntity,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = false
        };

        var result = await service.ImportParsedCertificateAsync(renewalParsed, trustDomainId,
            name: "renewing-client-2026", issuingCaId: caId);

        result.Success.ShouldBeTrue(result.Error);
        result.KeyPairedFrom.ShouldBe("renewing-client");

        await using var db = _dbFactory.CreateDbContext();
        var stored = await db.IssuedCertificates.FirstAsync(i => i.Thumbprint == renewalPublic.Thumbprint);
        var predecessor = await db.IssuedCertificates.FirstAsync(i => i.Thumbprint == original.Thumbprint);

        stored.EncryptedPfxBytes.ShouldNotBeNull();
        stored.PfxPassword.ShouldBe("orig-pw");
        stored.RenewalOfId.ShouldBe(predecessor.Id);
        stored.Version.ShouldBe(predecessor.Version + 1);

        using var reloaded = X509CertificateLoader.LoadPkcs12(stored.EncryptedPfxBytes!, "orig-pw",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        reloaded.HasPrivateKey.ShouldBeTrue();
        reloaded.Thumbprint.ShouldBe(renewalPublic.Thumbprint);
        reloaded.GetRSAPublicKey()!.ExportSubjectPublicKeyInfo().ShouldBe(rsa.ExportSubjectPublicKeyInfo());

        rsa.Dispose();
        originalParsed.Certificate.Dispose();
        renewalPublic.Dispose();
    }

    [Fact]
    public async Task ImportParsed_PublicOnlyCertWithUnknownPublicKey_StaysTrustOnly()
    {
        var (trustDomainId, caId) = await SeedTrustDomainWithCaAsync();
        var service = CreateService();

        var parsed = CreateParsedEndEntity();
        parsed.HasPrivateKey = false;
        parsed.RawFileBytes = parsed.Certificate.RawData;

        var result = await service.ImportParsedCertificateAsync(parsed, trustDomainId, issuingCaId: caId);

        result.Success.ShouldBeTrue(result.Error);
        result.KeyPairedFrom.ShouldBeNull();

        await using var db = _dbFactory.CreateDbContext();
        var stored = await db.IssuedCertificates.FirstAsync(i => i.Thumbprint == parsed.Certificate.Thumbprint);
        stored.EncryptedPfxBytes.ShouldBeNull();
        parsed.Certificate.Dispose();
    }

    #region Helpers

    private async Task<int> SeedTrustDomainAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Import Test", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();
        return trustDomain.Id;
    }

    private async Task<(int TrustDomainId, int CaId)> SeedTrustDomainWithCaAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Import Test", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Seed CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Seed-CA",
            Subject = "CN=Seed CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        return (trustDomain.Id, ca.Id);
    }

    private static ParsedCertificate CreateParsedRootCa(bool hasPrivateKey = true)
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Root CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = hasPrivateKey ? cert.Export(X509ContentType.Pkcs12, "test") : cert.RawData,
            FileName = "test-root.pfx",
            DetectedRole = DetectedCertRole.RootCa,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = hasPrivateKey
        };
    }

    private static ParsedCertificate CreateParsedIntermediateCa()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Intermediate CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = cert.Export(X509ContentType.Pkcs12, "test"),
            FileName = "test-intermediate.pfx",
            DetectedRole = DetectedCertRole.IntermediateCa,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = true
        };
    }

    private static ParsedCertificate CreateParsedEndEntity()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test End Entity", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = cert.Export(X509ContentType.Pkcs12, "test"),
            FileName = "test-client.pfx",
            DetectedRole = DetectedCertRole.EndEntity,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = true
        };
    }

    private static ParsedCertificate CreateParsedRootCaFrom(
        X509Certificate2 existingCert, bool hasPrivateKey = false)
    {
        var cert = X509CertificateLoader.LoadCertificate(existingCert.RawData);

        return new ParsedCertificate
        {
            Certificate = cert,
            RawFileBytes = cert.RawData,
            FileName = "dup.pfx",
            DetectedRole = DetectedCertRole.RootCa,
            Algorithm = "RSA",
            KeySize = 2048,
            HasPrivateKey = hasPrivateKey
        };
    }

    #endregion
}
