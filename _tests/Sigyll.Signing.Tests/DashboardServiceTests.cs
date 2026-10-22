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

public class DashboardServiceTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();

    private DashboardService CreateService() =>
        new(_dbFactory, TestOperators.Full, NullLogger<DashboardService>.Instance);

    [Fact]
    public async Task GetDashboard_EmptyDb_ReturnsZeroCounts()
    {
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainCount.ShouldBe(0);
        data.CaCertCount.ShouldBe(0);
        data.IssuedCertCount.ShouldBe(0);
        data.ProfileCount.ShouldBe(0);
        data.RevokedCertCount.ShouldBe(0);
        data.TrustDomainSummaries.ShouldBeEmpty();
        data.ExpiringCerts.ShouldBeEmpty();
        data.ExpiredCerts.ShouldBeEmpty();
        data.OverdueCrls.ShouldBeEmpty();
    }

    [Fact]
    public async Task GetDashboard_WithData_ReturnsCounts()
    {
        await SeedTrustDomainWithCertsAsync();
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainCount.ShouldBe(1);
        data.CaCertCount.ShouldBe(1);
        data.IssuedCertCount.ShouldBe(1);
    }

    [Fact]
    public async Task GetDashboard_ExpiredCert_AppearsInExpiredList()
    {
        await SeedTrustDomainWithCertsAsync(caNotAfter: DateTime.UtcNow.AddDays(-1));
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.ExpiredCerts.Where(c => c.CertType == "CA").ShouldHaveSingleItem();
    }

    [Fact]
    public async Task GetDashboard_ExpiringCert_AppearsInExpiringList()
    {
        await SeedTrustDomainWithCertsAsync(caNotAfter: DateTime.UtcNow.AddDays(30));
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.ExpiringCerts.Where(c => c.CertType == "CA").ShouldHaveSingleItem();
    }

    [Fact]
    public async Task GetDashboard_TrustDomainSummary_AggregatesCorrectly()
    {
        await SeedTrustDomainWithCertsAsync();
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainSummaries.ShouldHaveSingleItem();
        var summary = data.TrustDomainSummaries[0];
        summary.CaCount.ShouldBe(1);
        summary.IssuedCount.ShouldBe(1);
        summary.Name.ShouldBe("Test TrustDomain");
    }

    [Fact]
    public async Task GetDashboard_RevokedCert_CountedCorrectly()
    {
        await SeedTrustDomainWithCertsAsync(issuedRevoked: true);
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.RevokedCertCount.ShouldBe(1);
    }

    [Fact]
    public async Task GetDashboard_SupersededCrls_AreNotOverdue()
    {
        await SeedTrustDomainWithCertsAsync();
        await AddCrlsAsync(
            (ThisUpdate: DateTime.UtcNow.AddDays(-30), NextUpdate: DateTime.UtcNow.AddDays(-23)),
            (ThisUpdate: DateTime.UtcNow.AddDays(-7), NextUpdate: DateTime.UtcNow.AddDays(-1)),
            (ThisUpdate: DateTime.UtcNow.AddDays(-1), NextUpdate: DateTime.UtcNow.AddDays(6)));
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainSummaries[0].OverdueCrlCount.ShouldBe(0);
        data.OverdueCrls.ShouldBeEmpty();
    }

    [Fact]
    public async Task GetDashboard_NewestCrlPastNextUpdate_IsOverdue()
    {
        await SeedTrustDomainWithCertsAsync();
        await AddCrlsAsync(
            (ThisUpdate: DateTime.UtcNow.AddDays(-30), NextUpdate: DateTime.UtcNow.AddDays(-23)),
            (ThisUpdate: DateTime.UtcNow.AddDays(-9), NextUpdate: DateTime.UtcNow.AddDays(-2)));
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainSummaries[0].OverdueCrlCount.ShouldBe(1);
        data.OverdueCrls.ShouldHaveSingleItem().DaysOverdue.ShouldBe(2);
    }

    [Fact]
    public async Task GetDashboard_ArchivedAndRevokedCerts_AreLeftOutOfTheCards()
    {
        await SeedTrustDomainWithCertsAsync(issuedNotAfter: DateTime.UtcNow.AddDays(-5), issuedRevoked: true);
        await SeedTrustDomainWithCertsAsync(issuedNotAfter: DateTime.UtcNow.AddDays(-5), issuedArchived: true, trustDomainName: "Second");
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.IssuedCertCount.ShouldBe(1);
        var revokedDomain = data.TrustDomainSummaries.Single(d => d.Name == "Test TrustDomain");
        revokedDomain.IssuedCount.ShouldBe(1);
        revokedDomain.ExpiredIssuedCount.ShouldBe(0);
        var archivedDomain = data.TrustDomainSummaries.Single(d => d.Name == "Second");
        archivedDomain.IssuedCount.ShouldBe(0);
        archivedDomain.ExpiredIssuedCount.ShouldBe(0);
        data.ExpiredCerts.ShouldBeEmpty();
    }

    [Fact]
    public async Task GetDashboard_ExpiredWithAutoRenewOff_IsNotRenewingNotExpired()
    {
        await SeedTrustDomainWithCertsAsync(issuedNotAfter: DateTime.UtcNow.AddDays(-5), issuedAutoRenew: false);
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        var summary = data.TrustDomainSummaries.ShouldHaveSingleItem();
        summary.ExpiredIssuedCount.ShouldBe(0);
        summary.NotRenewingCount.ShouldBe(1);
        summary.IsHealthy.ShouldBeTrue();
        data.ExpiredCerts.ShouldBeEmpty();
        var row = data.NotRenewingCerts.ShouldHaveSingleItem();
        row.IsExpired.ShouldBeTrue();
        row.AutoRenew.ShouldBeFalse();
    }

    [Fact]
    public async Task GetDashboard_ExpiringWithAutoRenewOff_IsNotRenewingNotExpiring()
    {
        await SeedTrustDomainWithCertsAsync(issuedNotAfter: DateTime.UtcNow.AddDays(10), issuedAutoRenew: false);
        var service = CreateService();

        var data = await service.GetDashboardAsync();

        data.TrustDomainSummaries[0].ExpiringIssuedCount.ShouldBe(0);
        data.ExpiringCerts.ShouldBeEmpty();
        data.NotRenewingCerts.ShouldHaveSingleItem().IsExpired.ShouldBeFalse();
    }

    private async Task AddCrlsAsync(params (DateTime ThisUpdate, DateTime NextUpdate)[] crls)
    {
        await using var db = _dbFactory.CreateDbContext();
        var caId = await db.CaCertificates.Select(ca => ca.Id).SingleAsync();
        long number = 1;
        foreach (var (thisUpdate, nextUpdate) in crls)
        {
            db.Crls.Add(new Crl
            {
                CaCertificateId = caId,
                CrlNumber = number++,
                ThisUpdate = thisUpdate,
                NextUpdate = nextUpdate,
                SignatureAlgorithm = "sha256RSA",
                SignatureValid = true
            });
        }
        await db.SaveChangesAsync();
    }

    private async Task SeedTrustDomainWithCertsAsync(
        DateTime? caNotAfter = null,
        bool issuedRevoked = false,
        DateTime? issuedNotAfter = null,
        bool issuedArchived = false,
        string trustDomainName = "Test TrustDomain",
        bool issuedAutoRenew = true)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();

        var trustDomain = new TrustDomain { Name = trustDomainName, Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Test-CA",
            Subject = "CN=Test CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = DateTime.UtcNow.AddDays(-1),
            NotAfter = caNotAfter ?? DateTime.UtcNow.AddYears(1)
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = ca.Id,
            Name = "Test-Issued",
            Subject = "CN=Test Issued",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = "AABB" + cert.Thumbprint[4..],
            SerialNumber = "002",
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = DateTime.UtcNow.AddDays(-1),
            NotAfter = issuedNotAfter ?? DateTime.UtcNow.AddYears(1),
            IsRevoked = issuedRevoked,
            IsArchived = issuedArchived,
            AutoRenew = issuedAutoRenew,
            RevokedAt = issuedRevoked ? DateTime.UtcNow : null
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();
    }
}
