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
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Export;

namespace Sigyll.Signing.Tests;

public class VaultExportServiceTests
{
    private static readonly IOperatorContext Auditor = TestOperators.With(Permission.View);
    private static readonly IOperatorContext CaOperator = TestOperators.With(Permission.View, Permission.Operate);
    private static readonly IOperatorContext Admin = TestOperators.With(Permission.View, Permission.Operate, Permission.Administer);
    private static readonly IOperatorContext KeyCustodian = TestOperators.With(Permission.View, Permission.ExportKeys);

    private const string Token = "hvs.test";
    private static readonly Uri VaultAddress = new("https://vault.example.org:8200");

    private readonly TestDbContextFactory _dbFactory = new();
    private readonly IVaultKvClient _vault = Substitute.For<IVaultKvClient>();
    private readonly List<(string Path, IReadOnlyDictionary<string, string> Fields)> _writes = new();

    public VaultExportServiceTests()
    {
        _vault.MergeAsync(default!, default!, default!, default!, default!, default)
            .ReturnsForAnyArgs(call =>
            {
                _writes.Add((call.ArgAt<string>(3), call.ArgAt<IReadOnlyDictionary<string, string>>(4)));
                return _writes.Count;
            });
    }

    [Fact]
    public async Task PathMirrorsTheTrustDomainHierarchy_AtAnyDepth()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Team A Certs", "team-a");
        var root = await AddCaAsync(td, "Root CA");
        var issuing1 = await AddCaAsync(td, "Issuing CA 1", root);
        var issuing2 = await AddCaAsync(td, "Issuing CA 2", root);
        var policy = await AddCaAsync(td, "Policy CA", issuing2);
        var leaf = await AddIssuedAsync(policy, "payer server");

        await Service(CaOperator).ExportAsync(new("IssuedCertificate", leaf.Id, VaultExportArtifact.Cer), Token);
        await Service(CaOperator).ExportAsync(new("CaCertificate", issuing1, VaultExportArtifact.Cer), Token);

        _writes[0].Path.ShouldBe("team-a/team-a-certs/root-ca/issuing-ca-2/policy-ca/payer-server");
        _writes[0].Fields.Keys.ShouldBe(["payer server.cer"]);
        _writes[0].Fields["payer server.cer"].ShouldStartWith("-----BEGIN CERTIFICATE-----");
        _writes[1].Path.ShouldBe("team-a/team-a-certs/root-ca/issuing-ca-1");
        await _vault.Received(2).MergeAsync(VaultAddress, Token, "secret", Arg.Any<string>(),
            Arg.Any<IReadOnlyDictionary<string, string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FirstExportSetsTheNamespace_ThenOnlyAnAdminChangesIt()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", ns: null);
        var root = await AddCaAsync(td, "Root");
        var target = new VaultExportTarget("CaCertificate", root, VaultExportArtifact.Cer);

        (await Service(CaOperator).PlanAsync(target)).Namespace.ShouldBeNull();
        await Should.ThrowAsync<ArgumentException>(() => Service(CaOperator).ExportAsync(target, Token));

        await Service(CaOperator).ExportAsync(target, Token, firstNamespace: "/team-b/");
        _writes.Single().Path.ShouldBe("team-b/lab/root");
        (await Service(CaOperator).PlanAsync(target)).Namespace.ShouldBe("team-b");

        // Pointing an export elsewhere is refused, before anything is written.
        await Should.ThrowAsync<InvalidOperationException>(
            () => Service(CaOperator).ExportAsync(target, Token, firstNamespace: "elsewhere"));
        _writes.Count.ShouldBe(1);
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(CaOperator).SetTrustDomainNamespaceAsync(td, "elsewhere"));

        await Service(Admin).SetTrustDomainNamespaceAsync(td, "team-c");
        await Service(CaOperator).ExportAsync(target, Token);
        _writes[1].Path.ShouldBe("team-c/lab/root");
    }

    [Fact]
    public async Task NamespaceIsNotSetWhenVaultRefusesTheWrite()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", ns: null);
        var root = await AddCaAsync(td, "Root");
        _vault.MergeAsync(default!, default!, default!, default!, default!, default)
            .ReturnsForAnyArgs<int>(_ => throw new VaultTokenRefusedException("team-b/lab/root", 403));

        await Should.ThrowAsync<VaultTokenRefusedException>(() => Service(CaOperator)
            .ExportAsync(new("CaCertificate", root, VaultExportArtifact.Cer), Token, firstNamespace: "team-b"));

        (await Service(CaOperator).GetTrustDomainNamespacesAsync()).Single().Namespace.ShouldBeNull();
    }

    [Fact]
    public async Task P12_WritesTheFileAndItsPassword_ForKeyCustodiansOnly()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a");
        var root = await AddCaAsync(td, "Root");
        var leaf = await AddIssuedAsync(root, "client", withKey: true);
        var target = new VaultExportTarget("IssuedCertificate", leaf.Id, VaultExportArtifact.P12);

        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(Admin).ExportAsync(target, Token));
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(CaOperator).ExportAsync(target, Token));

        var result = await Service(KeyCustodian).ExportAsync(target, Token);

        result.Fields.ShouldBe(["client.p12", "password"], ignoreOrder: true);
        var (path, fields) = _writes.Single();
        path.ShouldBe("team-a/lab/root/client");
        fields["password"].ShouldBe("leaf-pass");
        using var pfx = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(fields["client.p12"]), "leaf-pass");
        pfx.HasPrivateKey.ShouldBeTrue();
    }

    [Fact]
    public async Task P12WithChain_UsesTheChainFileName()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a");
        var root = await AddCaAsync(td, "Root");
        var leaf = await AddIssuedAsync(root, "client", withKey: true);

        await Service(KeyCustodian).ExportAsync(new("IssuedCertificate", leaf.Id, VaultExportArtifact.P12WithChain), Token);

        _writes.Single().Fields.Keys.ShouldBe(["client-chain.p12", "password"], ignoreOrder: true);
    }

    [Fact]
    public async Task AuditorCannotExportToVault()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a");
        var root = await AddCaAsync(td, "Root");

        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => Service(Auditor).ExportAsync(new("CaCertificate", root, VaultExportArtifact.Cer), Token));
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(Auditor).ListNamespacesAsync(Token));
    }

    [Fact]
    public async Task CrlGoesIntoItsCasSecret()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a");
        var root = await AddCaAsync(td, "Root");
        var issuing = await AddCaAsync(td, "Issuing", root);
        int crlId;
        await using (var db = _dbFactory.CreateDbContext())
        {
            var crl = new Crl { CaCertificateId = issuing, CrlNumber = 7, RawBytes = [1, 2, 3], FileName = "issuing-7.crl" };
            db.Crls.Add(crl);
            await db.SaveChangesAsync();
            crlId = crl.Id;
        }

        await Service(CaOperator).ExportAsync(new("Crl", crlId, VaultExportArtifact.Crl), Token);

        var (path, fields) = _writes.Single();
        path.ShouldBe("team-a/lab/root/issuing");
        fields["Issuing.crl"].ShouldBe(Convert.ToBase64String([1, 2, 3]));
    }

    [Fact]
    public async Task UnrelatedSiblingsWithTheSameName_GetDistinctPaths_ButARenewalKeepsItsPath()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a");
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "Server", serial: "0A0B0C0D0E0F1011");
        var other = await AddIssuedAsync(root, "server", serial: "AABBCCDDEEFF0011");
        var renewal = await AddIssuedAsync(root, "Server", serial: "1234", renewalOf: first.Id);

        async Task<string> PathOf(int id) =>
            (await Service(CaOperator).PlanAsync(new("IssuedCertificate", id, VaultExportArtifact.Cer))).RelativePath;

        (await PathOf(first.Id)).ShouldBe("lab/root/server");
        (await PathOf(renewal.Id)).ShouldBe("lab/root/server");
        (await PathOf(other.Id)).ShouldBe("lab/root/server-eeff0011");
    }

    [Fact]
    public async Task TurnedOff_RefusesToPlanOrExport()
    {
        var td = await AddTrustDomainAsync("Lab", "team-a");
        var root = await AddCaAsync(td, "Root");
        var target = new VaultExportTarget("CaCertificate", root, VaultExportArtifact.Cer);

        await Should.ThrowAsync<InvalidOperationException>(() => Service(CaOperator).PlanAsync(target));
        await Should.ThrowAsync<InvalidOperationException>(() => Service(CaOperator).ExportAsync(target, Token));
        await _vault.DidNotReceiveWithAnyArgs().MergeAsync(default!, default!, default!, default!, default!, default);
    }

    [Fact]
    public async Task OnlyAnAdminChangesSettings_AndTheyAreValidated()
    {
        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => Service(KeyCustodian).SaveSettingsAsync(true, VaultAddress.ToString(), "secret"));
        await Should.ThrowAsync<ArgumentException>(() => Service(Admin).SaveSettingsAsync(true, null, "secret"));
        await Should.ThrowAsync<ArgumentException>(() => Service(Admin).SaveSettingsAsync(true, "ftp://vault", "secret"));
        await Should.ThrowAsync<ArgumentException>(() => Service(Admin).SaveSettingsAsync(true, VaultAddress.ToString(), "../x"));

        var saved = await Service(Admin).SaveSettingsAsync(true, "https://vault.example.org:8200/", "/kv/");

        saved.Address.ShouldBe("https://vault.example.org:8200");
        saved.Mount.ShouldBe("kv");
        (await Service(Auditor).GetSettingsAsync()).Enabled.ShouldBeTrue();
    }

    [Fact]
    public async Task ListNamespaces_ReturnsTheMountsFolders_OrNothingWhenTheTokenCannotList()
    {
        await EnableAsync();
        _vault.ListAsync(VaultAddress, Token, "secret", "", Arg.Any<CancellationToken>())
            .Returns(["team-b/", "team-a/", "loose-secret"]);

        (await Service(CaOperator).ListNamespacesAsync(Token)).ShouldBe(["team-a", "team-b"]);

        _vault.ListAsync(default!, default!, default!, default!, default)
            .ReturnsForAnyArgs<IReadOnlyList<string>>(_ => throw new VaultTokenRefusedException("", 403));
        (await Service(CaOperator).ListNamespacesAsync(Token)).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("Issuing CA / 2026", "issuing-ca-2026")]
    [InlineData("  ACME Server.example.org ", "acme-server.example.org")]
    [InlineData("///", "unnamed")]
    public void SlugMakesNamesPathSafe(string name, string expected) =>
        VaultExportService.Slug(name).ShouldBe(expected);

    private VaultExportService Service(IOperatorContext op) =>
        new(_dbFactory, op, new CertificateExportService(_dbFactory, op, NullLogger<CertificateExportService>.Instance),
            _vault, NullLogger<VaultExportService>.Instance);

    private async Task EnableAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        db.VaultExportSettings.Add(new VaultExportSettings { Enabled = true, Address = VaultAddress.ToString().TrimEnd('/'), Mount = "secret" });
        await db.SaveChangesAsync();
    }

    private async Task<int> AddTrustDomainAsync(string name, string? ns)
    {
        await using var db = _dbFactory.CreateDbContext();
        var td = new TrustDomain { Name = name, VaultNamespace = ns };
        db.TrustDomains.Add(td);
        await db.SaveChangesAsync();
        return td.Id;
    }

    private async Task<int> AddCaAsync(int trustDomainId, string name, int? parentId = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        var ca = new CaCertificate
        {
            TrustDomainId = trustDomainId,
            ParentId = parentId,
            Name = name,
            Subject = $"CN={name}",
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = Guid.NewGuid().ToString("N"),
            SerialNumber = Guid.NewGuid().ToString("N"),
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();
        return ca.Id;
    }

    private async Task<IssuedCertificate> AddIssuedAsync(
        int caId, string name, bool withKey = false, string? serial = null, int? renewalOf = null)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = caId,
            Name = name,
            Subject = $"CN={name}",
            X509CertificatePem = cert.ExportCertificatePem(),
            EncryptedPfxBytes = withKey ? cert.Export(X509ContentType.Pkcs12, "leaf-pass") : null,
            PfxPassword = withKey ? "leaf-pass" : null,
            Thumbprint = cert.Thumbprint,
            SerialNumber = serial ?? cert.SerialNumber,
            RenewalOfId = renewalOf,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();
        return issued;
    }
}
