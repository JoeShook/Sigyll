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
using NSubstitute;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Audit;
using Sigyll.Common.Services.Jobs;
using Sigyll.Common.Services.Signing;

namespace Sigyll.Signing.Tests;

public class AuditTrailTests
{
    private readonly TestDbContextFactory _dbFactory = new();

    private static readonly IOperatorContext Alice = TestOperators.As(
        new OperatorIdentity("alice@example.test", Enum.GetValues<Permission>().ToHashSet()));

    [Fact]
    public async Task Revoke_IsRecorded_WithTheOperatorTheCertificateAndTheReason()
    {
        var (_, issuedId, thumbprint) = await SeedAsync();

        (await Management(Alice).RevokeAsync(issuedId, "IssuedCertificate", 1)).Success.ShouldBeTrue();

        var e = (await EventsAsync()).Single(x => x.Action == AuditActions.CertificateRevoked);
        e.Actor.ShouldBe("alice@example.test");
        e.ActorIsSystem.ShouldBeFalse();
        e.Succeeded.ShouldBeTrue();
        e.EntityType.ShouldBe("IssuedCertificate");
        e.EntityId.ShouldBe(issuedId);
        e.Subject.ShouldBe("CN=client");
        e.Thumbprint.ShouldBe(thumbprint);
        e.TrustDomainId.ShouldNotBeNull();
        e.Detail!.ShouldContain("KeyCompromise");
    }

    [Fact]
    public async Task ExportPfx_IsRecorded_AndRefusedWhenTheRecordCannotBeStored()
    {
        var (_, issuedId, _) = await SeedAsync();

        var exported = await Export(new AuditTrail(_dbFactory, Alice)).ExportPfxAsync(issuedId, "IssuedCertificate", includeChain: false);
        exported.Success.ShouldBeTrue();
        var e = (await EventsAsync()).Single(x => x.Action == AuditActions.KeyExported);
        e.EntityId.ShouldBe(issuedId);
        e.Detail!.ShouldContain("PKCS #12");

        // No record, no key.
        var unrecorded = await Export(new AuditTrail(new BrokenDbContextFactory(), Alice))
            .ExportPfxAsync(issuedId, "IssuedCertificate", includeChain: false);
        unrecorded.Success.ShouldBeFalse();
        unrecorded.PfxBytes.ShouldBeNull();
    }

    [Fact]
    public async Task Delete_IsRecorded_AndTheRecordOutlivesTheCertificate()
    {
        var (_, issuedId, thumbprint) = await SeedAsync();

        (await Management(Alice).DeleteAsync(issuedId, "IssuedCertificate")).Success.ShouldBeTrue();

        await using (var db = _dbFactory.CreateDbContext())
            (await db.IssuedCertificates.AnyAsync(i => i.Id == issuedId)).ShouldBeFalse();
        var e = (await EventsAsync()).Single(x => x.Action == AuditActions.CertificateDeleted);
        e.EntityName.ShouldBe("client");
        e.Thumbprint.ShouldBe(thumbprint);
        e.Detail!.ShouldContain("private key");
    }

    [Fact]
    public async Task Search_FiltersAndPutsTheNewestFirst()
    {
        var (caId, issuedId, _) = await SeedAsync();
        var management = Management(Alice);
        await management.ArchiveAsync(caId, "CaCertificate");
        await management.RevokeAsync(issuedId, "IssuedCertificate", 0);
        await management.ArchiveAsync(issuedId, "IssuedCertificate");

        var all = await new AuditTrail(_dbFactory, TestOperators.With(Permission.View)).SearchAsync(new AuditQuery());
        all.Events.Select(e => e.Action).ShouldBe(
            [AuditActions.CertificateArchived, AuditActions.CertificateRevoked, AuditActions.CertificateArchived]);
        all.Events.Select(e => e.EntityType).ShouldBe(["IssuedCertificate", "IssuedCertificate", "CaCertificate"]);

        var archived = await new AuditTrail(_dbFactory, TestOperators.With(Permission.View))
            .SearchAsync(new AuditQuery(Action: AuditActions.CertificateArchived, Text: "root"));
        archived.Total.ShouldBe(1);
        archived.Events[0].EntityId.ShouldBe(caId);

        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => new AuditTrail(_dbFactory, TestOperators.Anonymous).SearchAsync(new AuditQuery()));
    }

    private CertificateManagementService Management(IOperatorContext operatorContext)
    {
        var httpFactory = Substitute.For<IHttpClientFactory>();
        httpFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient());
        return new CertificateManagementService(_dbFactory, operatorContext,
            NullLogger<CertificateManagementService>.Instance,
            new ChainValidationService(_dbFactory, operatorContext, httpFactory, NullLogger<ChainValidationService>.Instance),
            new CrlGenerationService(_dbFactory, operatorContext, NullLogger<CrlGenerationService>.Instance, new LocalSigningProvider()));
    }

    private CertificateExportService Export(AuditTrail audit) =>
        new(_dbFactory, Alice, NullLogger<CertificateExportService>.Instance, audit);

    private async Task<List<AuditEvent>> EventsAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        return await db.AuditEvents.OrderBy(e => e.Id).ToListAsync();
    }

    /// <summary>A root CA without its key and a client certificate it issued, with its key.</summary>
    private async Task<(int CaId, int IssuedId, string Thumbprint)> SeedAsync()
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var leafKey = RSA.Create(2048);
        using var leaf = new CertificateRequest("CN=client", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), RandomNumberGenerator.GetBytes(8));
        using var leafWithKey = leaf.CopyWithPrivateKey(leafKey);

        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Lab", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id, Name = "Test Root", Subject = root.Subject,
            X509CertificatePem = root.ExportCertificatePem(), Thumbprint = root.Thumbprint,
            SerialNumber = root.SerialNumber, KeyAlgorithm = "RSA", KeySize = 2048,
            NotBefore = root.NotBefore.ToUniversalTime(), NotAfter = root.NotAfter.ToUniversalTime(),
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = ca.Id, Name = "client", Subject = leaf.Subject,
            X509CertificatePem = leaf.ExportCertificatePem(), Thumbprint = leaf.Thumbprint,
            SerialNumber = leaf.SerialNumber, KeyAlgorithm = "RSA", KeySize = 2048,
            NotBefore = leaf.NotBefore.ToUniversalTime(), NotAfter = leaf.NotAfter.ToUniversalTime(),
            EncryptedPfxBytes = leafWithKey.Export(X509ContentType.Pkcs12, "leaf-pass"), PfxPassword = "leaf-pass",
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();
        return (ca.Id, issued.Id, leaf.Thumbprint);
    }

    /// <summary>A database that can't be reached.</summary>
    private sealed class BrokenDbContextFactory : IDbContextFactory<SigyllDbContext>
    {
        public SigyllDbContext CreateDbContext() => throw new InvalidOperationException("The database is unavailable.");
    }
}
