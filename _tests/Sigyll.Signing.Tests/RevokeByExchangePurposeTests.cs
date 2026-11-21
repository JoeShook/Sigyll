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
using Microsoft.Extensions.Options;
using NSubstitute;
using Sigyll.Contracts;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Audit;
using Sigyll.Common.Services.Jobs;
using Sigyll.Common.Services.Signing;
using Xunit;

namespace Sigyll.Signing.Tests;

public class RevokeByExchangePurposeTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();

    private CertificateManagementService CreateService(IOperatorContext operatorContext, string? queryParameterName = null)
    {
        var httpFactory = Substitute.For<IHttpClientFactory>();
        httpFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient());
        var chain = new ChainValidationService(_dbFactory, operatorContext, httpFactory,
            NullLogger<ChainValidationService>.Instance);
        var crl = new CrlGenerationService(_dbFactory, operatorContext,
            NullLogger<CrlGenerationService>.Instance, new LocalSigningProvider());
        return new CertificateManagementService(_dbFactory, operatorContext,
            NullLogger<CertificateManagementService>.Instance, chain, crl,
            exchangePurposeSan: Options.Create(new ExchangePurposeSanOptions { QueryParameterName = queryParameterName }));
    }

    [Fact]
    public async Task RevokesOnlyCertificatesCarryingTheExchangePurpose_AndPublishesACrl()
    {
        var caId = await SeedCaAsync();
        var treatment = await SeedIssuedAsync(caId, "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT");
        var queryForm = await SeedIssuedAsync(caId, "https://fhir.example.org/r4?purpose-param=T-TRTMNT");
        var payment = await SeedIssuedAsync(caId, "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-PYMNT");
        var ambiguous = await SeedIssuedAsync(caId, "https://fhir.example.org/T-PYMNT#T-TRTMNT");

        var ra = TestOperators.As(OperatorIdentity.System("ra-client", Permission.IssueFromRa, Permission.RevokeFromRa));
        var result = await CreateService(ra, "purpose-param").RevokeByExchangePurposeAsync(
            [treatment.ToLowerInvariant(), queryForm, payment, ambiguous, "DEADBEEF"], "T-TRTMNT", "Example Clinic (organization 7)", "ra@example.test");

        result.Success.ShouldBeTrue();
        result.Revoked.Order().ShouldBe(new[] { treatment, queryForm }.Order());
        result.Skipped.Keys.Order().ShouldBe(new[] { payment, ambiguous, "DEADBEEF" }.Order());
        result.Skipped[ambiguous].ShouldContain("ambiguous");
        result.CrlErrors.ShouldBeEmpty();

        await using var db = _dbFactory.CreateDbContext();
        var certs = await db.IssuedCertificates.ToListAsync();
        certs.Single(c => c.SerialNumber == ambiguous).IsRevoked.ShouldBeFalse();
        foreach (var c in certs.Where(c => c.SerialNumber != payment && c.SerialNumber != ambiguous))
        {
            c.IsRevoked.ShouldBeTrue();
            c.RevocationReason.ShouldBe((int)X509RevocationReason.PrivilegeWithdrawn);
        }
        certs.Single(c => c.SerialNumber == payment).IsRevoked.ShouldBeFalse();

        (await db.Crls.CountAsync(c => c.CaCertificateId == caId)).ShouldBe(1);

        var events = await db.AuditEvents.ToListAsync();
        events.Count(e => e.Action == AuditActions.CertificateRevoked).ShouldBe(2);
        var summary = events.Single(e => e.Action == AuditActions.CertificatesRevokedByExchangePurpose);
        summary.Actor.ShouldBe("ra-client");
        summary.Detail!.ShouldContain("T-TRTMNT");
        summary.Detail.ShouldContain("Example Clinic");
        summary.Detail.ShouldContain("ra@example.test");
        events.ShouldContain(e => e.Action == AuditActions.CrlGenerated);
    }

    [Fact]
    public async Task AlreadyRevokedCertificatesAreSkipped()
    {
        var caId = await SeedCaAsync();
        var serial = await SeedIssuedAsync(caId, "urn:oid:1.2.3#T-TRTMNT", revoked: true);

        var result = await CreateService(TestOperators.Full).RevokeByExchangePurposeAsync(
            [serial], "T-TRTMNT", "org", "ra");

        result.Revoked.ShouldBeEmpty();
        result.Skipped[serial].ShouldBe("Already revoked.");
        await using var db = _dbFactory.CreateDbContext();
        (await db.Crls.CountAsync()).ShouldBe(0);
    }

    [Fact]
    public async Task RejectsSomethingThatIsNotAnExchangePurpose()
    {
        var result = await CreateService(TestOperators.Full).RevokeByExchangePurposeAsync(
            ["01"], "treatment", "org", "ra");

        result.Success.ShouldBeFalse();
    }

    [Fact]
    public async Task TheRaClientMayNotUseOrdinaryRevocation()
    {
        var caId = await SeedCaAsync();
        var ra = TestOperators.As(OperatorIdentity.System("ra-client", Permission.IssueFromRa, Permission.RevokeFromRa));

        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => CreateService(ra).RevokeAsync(caId, "CaCertificate", 1));
    }

    private async Task<int> SeedCaAsync()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=XP Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "XP", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "XP Test CA",
            Subject = cert.Subject,
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = cert.Export(X509ContentType.Pkcs12, "test"),
            PfxPassword = "test",
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();
        return ca.Id;
    }

    private async Task<string> SeedIssuedAsync(int caId, string sanUri, bool revoked = false)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri(sanUri));
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        db.IssuedCertificates.Add(new IssuedCertificate
        {
            IssuingCaCertificateId = caId,
            Name = $"client-{cert.SerialNumber}",
            Subject = cert.Subject,
            SubjectAltNames = $"Uri:{sanUri}",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            IsRevoked = revoked,
            RevokedAt = revoked ? DateTime.UtcNow : null,
            RevocationReason = revoked ? 1 : 0,
        });
        await db.SaveChangesAsync();
        return cert.SerialNumber;
    }
}
