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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;

namespace Sigyll.Signing.Tests;

/// <summary>
/// The scenario: a certificate issued by an external CA was imported with its private key, and the
/// external CA now wants a CSR for renewal. The CSR must be modeled on that certificate — same
/// subject, same SANs, requested extensions — and signed by either its existing key or a new one.
/// </summary>
public class CsrGenerationServiceTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();
    private readonly CsrGenerationService _service;

    private const string SanUri = "https://fhir.example.org/r4";
    private const string SanDns = "fhir.example.org";

    public CsrGenerationServiceTests()
    {
        _service = new CsrGenerationService(_dbFactory, TestOperators.Full, NullLogger<CsrGenerationService>.Instance);
    }

    [Fact]
    public async Task ReuseExistingKey_ProducesCsrSignedByThatKeyWithSameSubjectAndSans()
    {
        var (id, entityType, original) = await SeedImportedEndEntityAsync();

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = entityType,
            KeyMode = CsrKeyMode.ReuseExistingKey
        });

        result.Success.ShouldBeTrue(result.Error);
        result.EncryptedPrivateKeyPem.ShouldBeNull();
        result.KeyAlgorithm.ShouldBe("RSA");
        result.KeySize.ShouldBe(2048);
        result.SuggestedFileName.ShouldBe("udap-client.csr");

        // LoadSigningRequestPem verifies the PKCS#10 signature unless told to skip it
        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        csr.SubjectName.RawData.ShouldBe(original.SubjectName.RawData);
        csr.PublicKey.ExportSubjectPublicKeyInfo().ShouldBe(original.PublicKey.ExportSubjectPublicKeyInfo());

        var sans = csr.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        sans.Format(false).ShouldContain(SanUri);
        sans.EnumerateDnsNames().ShouldContain(SanDns);

        // KU / EKU copied as requested extensions
        csr.CertificateExtensions.OfType<X509KeyUsageExtension>().Single()
            .KeyUsages.ShouldBe(X509KeyUsageFlags.DigitalSignature);
        csr.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().Single()
            .EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ShouldContain("1.3.6.1.5.5.7.3.2");

        result.PublicKeyThumbprint.ShouldBe(
            Convert.ToHexString(SHA256.HashData(original.PublicKey.ExportSubjectPublicKeyInfo())));
    }

    [Fact]
    public async Task GenerateNewKey_ReturnsEncryptedKeyMatchingCsrPublicKey()
    {
        var (id, entityType, original) = await SeedImportedEndEntityAsync();

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = entityType,
            KeyMode = CsrKeyMode.GenerateNewKey,
            NewKeyAlgorithm = "ECDSA",
            NewKeySize = 384,
            NewKeyPassphrase = "keep-me-safe"
        });

        result.Success.ShouldBeTrue(result.Error);
        result.KeyAlgorithm.ShouldBe("ECDSA");
        result.KeySize.ShouldBe(384);
        result.EncryptedPrivateKeyPem.ShouldNotBeNull();
        result.EncryptedPrivateKeyPem.ShouldContain("ENCRYPTED PRIVATE KEY");

        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256);
        csr.PublicKey.ExportSubjectPublicKeyInfo().ShouldNotBe(original.PublicKey.ExportSubjectPublicKeyInfo());

        using var key = ECDsa.Create();
        key.ImportFromEncryptedPem(result.EncryptedPrivateKeyPem, "keep-me-safe");
        key.ExportSubjectPublicKeyInfo().ShouldBe(csr.PublicKey.ExportSubjectPublicKeyInfo());

        // Subject is still modeled on the original certificate
        csr.SubjectName.Name.ShouldBe(original.Subject);
    }

    [Fact]
    public async Task GenerateNewKey_WithoutPassphrase_Fails()
    {
        var (id, entityType, _) = await SeedImportedEndEntityAsync();

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = entityType,
            KeyMode = CsrKeyMode.GenerateNewKey
        });

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("passphrase", Case.Insensitive);
    }

    [Fact]
    public async Task OverridingSubjectAndSans_UsesTheProvidedValues()
    {
        var (id, entityType, _) = await SeedImportedEndEntityAsync();

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = entityType,
            KeyMode = CsrKeyMode.ReuseExistingKey,
            SubjectDn = "CN=Renamed Client, O=My Org",
            SubjectAltNames =
            [
                new SanEntry(SanType.Uri, "https://new.example.org/fhir"),
                new SanEntry(SanType.Email, "ops@example.org")
            ],
            IncludeExistingExtensions = false
        });

        result.Success.ShouldBeTrue(result.Error);

        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        csr.SubjectName.Name.ShouldBe("CN=Renamed Client, O=My Org");
        var sans = csr.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        var formatted = sans.Format(false);
        formatted.ShouldContain("https://new.example.org/fhir");
        formatted.ShouldContain("ops@example.org");
        formatted.ShouldNotContain(SanUri);
        sans.EnumerateDnsNames().ShouldBeEmpty();
        csr.CertificateExtensions.OfType<X509KeyUsageExtension>().ShouldBeEmpty();
    }

    [Fact]
    public async Task ReuseExistingKey_WhenNoKeyStored_Fails()
    {
        var (id, entityType, _) = await SeedImportedEndEntityAsync(includePrivateKey: false);

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = entityType,
            KeyMode = CsrKeyMode.ReuseExistingKey
        });

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("No private key");
    }

    [Fact]
    public async Task WorksForCaCertificateEntities()
    {
        var id = await SeedImportedSubCaAsync();

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = "CaCertificate",
            KeyMode = CsrKeyMode.ReuseExistingKey
        });

        result.Success.ShouldBeTrue(result.Error);
        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        csr.CertificateExtensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority.ShouldBeTrue();
    }

    [Fact]
    public void FromCertificate_Pkcs12InMemory_NoDatabaseNoCa_ProducesCsrSignedByItsKey()
    {
        // The stand-alone flow: operator uploads a .p12 issued by some external CA
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Standalone Client, O=Somewhere", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(SanUri));
        sanBuilder.AddEmailAddress("ops@example.org");
        req.CertificateExtensions.Add(sanBuilder.Build());
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var withKey = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var p12 = withKey.Export(X509ContentType.Pkcs12, "p12-pw");

        using var loaded = X509CertificateLoader.LoadPkcs12(p12, "p12-pw",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        var result = _service.GenerateCsrFromCertificate(loaded, "my-client.p12", new CsrGenerationRequest
        {
            KeyMode = CsrKeyMode.ReuseExistingKey
        });

        result.Success.ShouldBeTrue(result.Error);
        result.SuggestedFileName.ShouldBe("my-client.p12.csr");

        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        csr.SubjectName.RawData.ShouldBe(withKey.SubjectName.RawData);
        csr.PublicKey.ExportSubjectPublicKeyInfo().ShouldBe(rsa.ExportSubjectPublicKeyInfo());
        csr.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Single().Format(false).ShouldContain(SanUri);

        // Nothing touched the database
        using var db = _dbFactory.CreateDbContext();
        db.IssuedCertificates.Count().ShouldBe(0);
        db.CaCertificates.Count().ShouldBe(0);
    }

    [Fact]
    public void FromCertificate_PublicOnly_ReuseKeyFails_NewKeyWorks()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Public Only", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var withKey = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.RawData);
        publicOnly.HasPrivateKey.ShouldBeFalse();

        var reuse = _service.GenerateCsrFromCertificate(publicOnly, "x", new CsrGenerationRequest { KeyMode = CsrKeyMode.ReuseExistingKey });
        reuse.Success.ShouldBeFalse();
        reuse.Error.ShouldNotBeNull();
        reuse.Error.ShouldContain("No private key");

        var fresh = _service.GenerateCsrFromCertificate(publicOnly, "x", new CsrGenerationRequest
        {
            KeyMode = CsrKeyMode.GenerateNewKey,
            NewKeyAlgorithm = "RSA",
            NewKeySize = 3072,
            NewKeyPassphrase = "pw"
        });
        fresh.Success.ShouldBeTrue(fresh.Error);
        fresh.KeySize.ShouldBe(3072);
        fresh.EncryptedPrivateKeyPem.ShouldNotBeNull();
    }

    [Fact]
    public async Task UriSanWithoutPath_IsPreservedExactly_NoTrailingSlash()
    {
        // .NET's SubjectAlternativeNameBuilder would emit "https://host/" — UDAP needs the exact base URL
        var (id, entityType, _) = await SeedImportedEndEntityAsync();
        const string bareHost = "https://idp.example.org";

        var result = await _service.GenerateCsrAsync(new CsrGenerationRequest
        {
            CertificateId = id,
            EntityType = entityType,
            KeyMode = CsrKeyMode.ReuseExistingKey,
            SubjectAltNames = [new SanEntry(SanType.Uri, bareHost)]
        });

        result.Success.ShouldBeTrue(result.Error);

        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var sanExt = csr.CertificateExtensions.Single(e => e.Oid?.Value == "2.5.29.17");

        // Re-read with the same BouncyCastle-based reader the UI uses
        using var probe = MakeCertWithExtension(sanExt);
        var sans = CsrGenerationService.ExtractSubjectAltNames(probe);
        sans.ShouldBe([new SanEntry(SanType.Uri, bareHost)]);
        sanExt.Format(false).ShouldNotContain(bareHost + "/");
    }

    [Fact]
    public void SanExtensionBuilder_PreservesUriText_AndEncodesAllTypes()
    {
        var ext = SanExtensionBuilder.Build(
        [
            new SanEntry(SanType.Uri, "https://host.example"),          // no path — must NOT gain "/"
            new SanEntry(SanType.Uri, "https://host.example/fhir/r4"),
            new SanEntry(SanType.Dns, "host.example"),
            new SanEntry(SanType.Email, "ops@host.example"),
            new SanEntry(SanType.IpAddress, "10.1.2.3"),
            new SanEntry(SanType.Dns, "   ")                             // blank — skipped
        ]);

        ext.ShouldNotBeNull();
        ext.Critical.ShouldBeFalse();
        using var probe = MakeCertWithExtension(ext);
        var sans = CsrGenerationService.ExtractSubjectAltNames(probe);
        sans.ShouldBe(
        [
            new SanEntry(SanType.Uri, "https://host.example"),
            new SanEntry(SanType.Uri, "https://host.example/fhir/r4"),
            new SanEntry(SanType.Dns, "host.example"),
            new SanEntry(SanType.Email, "ops@host.example"),
            new SanEntry(SanType.IpAddress, "10.1.2.3")
        ]);

        SanExtensionBuilder.Build([new SanEntry(SanType.Dns, "")]).ShouldBeNull();
        Should.Throw<ArgumentException>(() => SanExtensionBuilder.Build([new SanEntry(SanType.Uri, "not a uri")]));
        Should.Throw<ArgumentException>(() => SanExtensionBuilder.Build([new SanEntry(SanType.IpAddress, "999.1.1.1")]));
    }

    /// <summary>Wraps an extension in a throwaway self-signed certificate so it can be read back through X509Certificate2.</summary>
    private static X509Certificate2 MakeCertWithExtension(X509Extension extension)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=probe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(extension.Oid!, extension.RawData, extension.Critical));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact]
    public void ExtractSubjectAltNames_ReturnsUriDnsEmailAndIp()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=SAN Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(SanUri));
        sanBuilder.AddDnsName(SanDns);
        sanBuilder.AddEmailAddress("ops@example.org");
        sanBuilder.AddIpAddress(System.Net.IPAddress.Parse("10.1.2.3"));
        req.CertificateExtensions.Add(sanBuilder.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var sans = CsrGenerationService.ExtractSubjectAltNames(cert);

        sans.ShouldContain(new SanEntry(SanType.Uri, SanUri));
        sans.ShouldContain(new SanEntry(SanType.Dns, SanDns));
        sans.ShouldContain(new SanEntry(SanType.Email, "ops@example.org"));
        sans.ShouldContain(new SanEntry(SanType.IpAddress, "10.1.2.3"));
        sans.Count.ShouldBe(4);
    }

    // --- Seeding ---

    /// <summary>
    /// An end-entity certificate issued by an "external" CA (only the CA's public cert is stored,
    /// as a trust anchor) and imported with its private key, the way the importer stores a PFX.
    /// </summary>
    private async Task<(int Id, string EntityType, X509Certificate2 PublicCert)> SeedImportedEndEntityAsync(
        bool includePrivateKey = true)
    {
        using var caRsa = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=External Issuing CA, O=Somebody Else", caRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(10));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=UDAP Client, OU=Integration, O=My Org, C=US",
            leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.2")], false));
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri(SanUri));
        sanBuilder.AddDnsName(SanDns);
        leafReq.CertificateExtensions.Add(sanBuilder.Build());

        var serial = RandomNumberGenerator.GetBytes(12);
        serial[0] &= 0x7F;
        using var leafPublic = leafReq.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), serial);
        using var leafWithKey = leafPublic.CopyWithPrivateKey(leafRsa);

        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "CSR Test", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "external-ca",
            Subject = caCert.Subject,
            X509CertificatePem = caCert.ExportCertificatePem(),
            Thumbprint = caCert.Thumbprint,
            SerialNumber = caCert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = caCert.NotBefore.ToUniversalTime(),
            NotAfter = caCert.NotAfter.ToUniversalTime()
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = ca.Id,
            Name = "udap client",
            Subject = leafWithKey.Subject,
            X509CertificatePem = leafWithKey.ExportCertificatePem(),
            EncryptedPfxBytes = includePrivateKey ? leafWithKey.Export(X509ContentType.Pkcs12, "pw") : null,
            PfxPassword = includePrivateKey ? "pw" : null,
            Thumbprint = leafWithKey.Thumbprint,
            SerialNumber = leafWithKey.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = leafWithKey.NotBefore.ToUniversalTime(),
            NotAfter = leafWithKey.NotAfter.ToUniversalTime(),
            CertSecurityLevel = CertSecurityLevel.Software,
            Enabled = true
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();

        return (issued.Id, "IssuedCertificate", X509CertificateLoader.LoadCertificate(leafPublic.RawData));
    }

    private async Task<int> SeedImportedSubCaAsync()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Imported Sub CA, O=My Org", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "CSR CA Test", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "imported-sub-ca",
            Subject = cert.Subject,
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = cert.Export(X509ContentType.Pkcs12, "pw"),
            PfxPassword = "pw",
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            CertSecurityLevel = CertSecurityLevel.Software,
            Enabled = true
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();
        return ca.Id;
    }
}
