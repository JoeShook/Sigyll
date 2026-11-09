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
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>A renewal or re-key keeps the predecessor's subject and SANs; changing them needs a new certificate.</summary>
public class RenewalIdentityTests
{
    private readonly TestDbContextFactory _dbFactory = new();

    private CertificateIssuanceService CreateService() =>
        new(_dbFactory, TestOperators.Full, NullLogger<CertificateIssuanceService>.Instance);

    [Fact]
    public async Task Renewal_ThatAddsAUri_IsRefused()
    {
        var (seed, first) = await IssueFirstAsync();

        var second = await CreateService().IssueCertificateAsync(Renewal(seed, first,
            "CN=api.example.com",
            new SanEntry(SanType.Dns, "api.example.com"),
            new SanEntry(SanType.Uri, "https://api.example.com/fhir/r4")));

        second.Success.ShouldBeFalse();
        second.Error!.ShouldContain("adds Uri:https://api.example.com/fhir/r4");
    }

    [Fact]
    public async Task Renewal_ThatRemovesASan_IsRefused()
    {
        var (seed, first) = await IssueFirstAsync(new SanEntry(SanType.Dns, "www.example.com"));

        var second = await CreateService().IssueCertificateAsync(Renewal(seed, first,
            "CN=api.example.com", new SanEntry(SanType.Dns, "api.example.com")));

        second.Success.ShouldBeFalse();
        second.Error!.ShouldContain("removes Dns:www.example.com");
    }

    [Fact]
    public async Task Renewal_ThatChangesTheSubject_IsRefused()
    {
        var (seed, first) = await IssueFirstAsync();

        var second = await CreateService().IssueCertificateAsync(Renewal(seed, first,
            "CN=other.example.com", new SanEntry(SanType.Dns, "api.example.com")));

        second.Success.ShouldBeFalse();
        second.Error!.ShouldContain("subject changes");
    }

    [Fact]
    public async Task Renewal_WithTheSameNames_InAnotherOrderAndCase_Succeeds()
    {
        var (seed, first) = await IssueFirstAsync(new SanEntry(SanType.Dns, "www.example.com"));

        var second = await CreateService().IssueCertificateAsync(Renewal(seed, first,
            "cn=API.example.com",
            new SanEntry(SanType.Dns, "WWW.example.com"),
            new SanEntry(SanType.Dns, "api.example.com")));

        second.Success.ShouldBeTrue(second.Error);
    }

    [Fact]
    public async Task CsrRenewal_ThatChangesTheSubject_IsRefused()
    {
        var (seed, first) = await IssueFirstAsync();

        using var key = RSA.Create(2048);
        var csr = new CertificateRequest("CN=other.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequestPem();
        var second = await CreateService().IssueCertificateFromCsrAsync(new CsrIssuanceRequest
        {
            IssuingCaCertificateId = seed.CaId,
            ProfileId = seed.ProfileId,
            TrustDomainId = seed.TrustDomainId,
            CsrPem = csr,
            SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com")],
            RenewalOfCertificateId = first,
        });

        second.Success.ShouldBeFalse();
        second.Error!.ShouldContain("subject changes");
    }

    [Fact]
    public async Task CompatibleProfile_MatchesCaFlagKeyUsageEkuAndRequiredSanTypes()
    {
        var (seed, first) = await IssueFirstAsync();
        await using var db = _dbFactory.CreateDbContext();
        var issued = await db.IssuedCertificates.FindAsync(first);
        using var cert = X509Certificate2.CreateFromPem(issued!.X509CertificatePem);
        var profile = (await db.CertificateProfiles.FindAsync(seed.ProfileId))!;
        List<SanEntry> sans = [new(SanType.Dns, "api.example.com")];

        RenewalIdentity.IsCompatibleProfile(profile, cert, sans).ShouldBeTrue();

        profile.KeyAlgorithm = "ECDSA";
        RenewalIdentity.IsCompatibleProfile(profile, cert, sans).ShouldBeTrue("a re-key may change the algorithm");

        profile.ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.2";
        RenewalIdentity.IsCompatibleProfile(profile, cert, sans).ShouldBeFalse("client auth instead of server auth");

        profile.ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1";
        profile.SubjectAltNameTypes = "URI";
        RenewalIdentity.IsCompatibleProfile(profile, cert, sans).ShouldBeFalse("would require a URI the certificate lacks");

        profile.SubjectAltNameTypes = null;
        profile.KeyUsageFlags = (int)(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        RenewalIdentity.IsCompatibleProfile(profile, cert, sans).ShouldBeFalse("different key usages");
    }

    private sealed record Seed(int CaId, int ProfileId, int TrustDomainId);

    private static CertificateIssuanceRequest Renewal(Seed seed, int predecessorId, string subjectDn, params SanEntry[] sans) => new()
    {
        IssuingCaCertificateId = seed.CaId,
        ProfileId = seed.ProfileId,
        TrustDomainId = seed.TrustDomainId,
        SubjectDn = subjectDn,
        CertificateName = "api (2)",
        PfxPassword = "test-password",
        SubjectAltNames = [.. sans],
        RenewalOfCertificateId = predecessorId,
    };

    private async Task<(Seed Seed, int FirstId)> IssueFirstAsync(params SanEntry[] extraSans)
    {
        var seed = await SeedAsync();
        var first = await CreateService().IssueCertificateAsync(new CertificateIssuanceRequest
        {
            IssuingCaCertificateId = seed.CaId,
            ProfileId = seed.ProfileId,
            TrustDomainId = seed.TrustDomainId,
            SubjectDn = "CN=api.example.com",
            CertificateName = "api",
            PfxPassword = "test-password",
            SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com"), .. extraSans],
        });
        first.Success.ShouldBeTrue(first.Error);
        return (seed, first.EntityId!.Value);
    }

    private async Task<Seed> SeedAsync()
    {
        await using var db = _dbFactory.CreateDbContext();

        var trustDomain = new TrustDomain { Name = "Test TD", Enabled = true };
        db.TrustDomains.Add(trustDomain);

        var profile = new CertificateProfile
        {
            Name = "SSL Server",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            IsKeyUsageCritical = true,
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            HashAlgorithm = "SHA256",
        };
        db.CertificateProfiles.Add(profile);

        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test Issuing CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Test Issuing CA",
            Subject = "CN=Test Issuing CA",
            X509CertificatePem = caCert.ExportCertificatePem(),
            EncryptedPfxBytes = caCert.Export(X509ContentType.Pkcs12, "test"),
            PfxPassword = "test",
            Thumbprint = caCert.Thumbprint,
            SerialNumber = caCert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter,
        };
        db.CaCertificates.Add(ca);

        await db.SaveChangesAsync();
        return new Seed(ca.Id, profile.Id, trustDomain.Id);
    }
}
