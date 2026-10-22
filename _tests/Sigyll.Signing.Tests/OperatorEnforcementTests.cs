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
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Jobs;
using Sigyll.Common.Services.Signing;
using Sigyll.Common.ViewModels;

namespace Sigyll.Signing.Tests;

/// <summary>What each role can and cannot do, checked at the services rather than the pages.</summary>
public class OperatorEnforcementTests
{
    private static readonly IOperatorContext Auditor = TestOperators.With(Permission.View);
    private static readonly IOperatorContext CaOperator = TestOperators.With(Permission.View, Permission.Operate);
    private static readonly IOperatorContext Admin = TestOperators.With(Permission.View, Permission.Operate, Permission.Administer);
    private static readonly IOperatorContext KeyCustodian = TestOperators.With(Permission.View, Permission.ExportKeys);
    private static readonly IOperatorContext RaClient = TestOperators.As(OperatorIdentity.System("ra-client", Permission.IssueFromRa));

    private readonly TestDbContextFactory _dbFactory = new();
    private readonly IRemoteKeyStore _remoteKeys = Substitute.For<IRemoteKeyStore>();

    [Fact]
    public async Task AuditorCanReadButNotRevokeOrDelete()
    {
        var caId = await SeedCaAsync();
        var service = Management(Auditor);

        (await service.GetNodeDetailsAsync(caId, "CaCertificate")).ShouldNotBeNull();
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => service.RevokeAsync(caId, "CaCertificate", 0));
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => service.DeleteAsync(caId, "CaCertificate"));
    }

    [Fact]
    public async Task CaOperatorCannotDeleteOrDestroyKeys()
    {
        var caId = await SeedCaAsync(storeProviderHint: "vault-transit:sigil-test");

        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Management(CaOperator).DeleteAsync(caId, "CaCertificate"));

        await _remoteKeys.DidNotReceiveWithAnyArgs().DestroyKeyAsync(default);
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.FindAsync(caId)).ShouldNotBeNull();
    }

    [Fact]
    public async Task AdminDelete_DestroysTheRemoteKey_AfterTheRowIsGone()
    {
        var caId = await SeedCaAsync(storeProviderHint: "vault-transit:sigil-test");
        bool? rowExistedWhenKeyDestroyed = null;
        _remoteKeys.When(k => k.DestroyKeyAsync("vault-transit:sigil-test", Arg.Any<CancellationToken>()))
            .Do(_ =>
            {
                using var db = _dbFactory.CreateDbContext();
                rowExistedWhenKeyDestroyed = db.CaCertificates.Any(c => c.Id == caId);
            });

        var result = await Management(Admin).DeleteAsync(caId, "CaCertificate");

        result.Success.ShouldBeTrue();
        result.Warning.ShouldBeNull();
        rowExistedWhenKeyDestroyed.ShouldBe(false);
    }

    [Fact]
    public async Task AdminDelete_RemoteKeyFailure_StillDeletes_AndWarns()
    {
        var caId = await SeedCaAsync(storeProviderHint: "gcp-kms:sigil-test");
        _remoteKeys.DestroyKeyAsync(Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("kms unavailable"));

        var result = await Management(Admin).DeleteAsync(caId, "CaCertificate");

        result.Success.ShouldBeTrue();
        result.Warning!.ShouldContain("kms unavailable");
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.FindAsync(caId)).ShouldBeNull();
    }

    [Fact]
    public async Task OnlyKeyCustodianExportsKeys()
    {
        var caId = await SeedCaAsync(withKey: true);

        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Export(Admin).ExportPfxAsync(caId, "CaCertificate", false));
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Export(CaOperator).ExportPfxAsync(caId, "CaCertificate", false));

        var pfx = await Export(KeyCustodian).ExportPfxAsync(caId, "CaCertificate", false);
        pfx.Success.ShouldBeTrue(pfx.Error);
    }

    [Fact]
    public async Task RaClientCanOnlyIssueFromACsr()
    {
        var issuance = new CertificateIssuanceService(_dbFactory, RaClient, NullLogger<CertificateIssuanceService>.Instance);

        // Passes the permission check, then fails on the (missing) profile.
        var fromCsr = await issuance.IssueCertificateFromCsrAsync(new CsrIssuanceRequest { ProfileId = 999 });
        fromCsr.Success.ShouldBeFalse();

        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => issuance.IssueCertificateAsync(new CertificateIssuanceRequest()));
        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => Management(RaClient).GetTrustDomainTreeAsync(1));
    }

    private CertificateManagementService Management(IOperatorContext op) =>
        new(_dbFactory, op, NullLogger<CertificateManagementService>.Instance,
            new ChainValidationService(_dbFactory, op, Substitute.For<IHttpClientFactory>(), NullLogger<ChainValidationService>.Instance),
            new CrlGenerationService(_dbFactory, op, NullLogger<CrlGenerationService>.Instance, new LocalSigningProvider()),
            remoteKeys: _remoteKeys);

    private CertificateExportService Export(IOperatorContext op) =>
        new(_dbFactory, op, NullLogger<CertificateExportService>.Instance);

    private async Task<int> SeedCaAsync(string? storeProviderHint = null, bool withKey = false)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Enforcement CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Enforcement", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Enforcement CA",
            Subject = "CN=Enforcement CA",
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = withKey ? cert.Export(X509ContentType.Pkcs12, "test") : null,
            PfxPassword = withKey ? "test" : null,
            StoreProviderHint = storeProviderHint,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();
        return ca.Id;
    }
}
