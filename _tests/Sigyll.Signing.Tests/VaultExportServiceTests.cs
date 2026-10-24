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
    private readonly List<(string Path, IReadOnlyCollection<string> Removed)> _removes = new();

    /// <summary>The field names each secret already has in Vault, by path.</summary>
    private readonly Dictionary<string, string[]> _existing = new();

    public VaultExportServiceTests()
    {
        _vault.ReadFieldNamesAsync(default!, default!, default!, default!, default)
            .ReturnsForAnyArgs(call => (IReadOnlyCollection<string>)(call.ArgAt<string>(3) is { } path ? _existing.GetValueOrDefault(path, []) : []));
        _vault.MergeAsync(default!, default!, default!, default!, default!, default, default)
            .ReturnsForAnyArgs(call =>
            {
                _writes.Add((call.ArgAt<string>(3), call.ArgAt<IReadOnlyDictionary<string, string>>(4)));
                _removes.Add((call.ArgAt<string>(3), call.ArgAt<IReadOnlyCollection<string>?>(5) ?? []));
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
            Arg.Any<IReadOnlyDictionary<string, string>>(), Arg.Any<IReadOnlyCollection<string>?>(), Arg.Any<CancellationToken>());
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
        _vault.MergeAsync(default!, default!, default!, default!, default!, default, default)
            .ReturnsForAnyArgs<int>(_ => throw new VaultTokenRefusedException("team-b/lab/root", 403));

        await Should.ThrowAsync<VaultTokenRefusedException>(() => Service(CaOperator)
            .ExportAsync(new("CaCertificate", root, VaultExportArtifact.Cer), Token, firstNamespace: "team-b"));

        (await Service(CaOperator).GetTrustDomainVaultSettingsAsync()).Single().Namespace.ShouldBeNull();
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
        var renamed = await AddIssuedAsync(root, "Server (renewed)", serial: "5678", renewalOf: renewal.Id);

        async Task<string> PathOf(int id) =>
            (await Service(CaOperator).PlanAsync(new("IssuedCertificate", id, VaultExportArtifact.Cer))).RelativePath;

        (await PathOf(first.Id)).ShouldBe("lab/root/server");
        (await PathOf(renewal.Id)).ShouldBe("lab/root/server");
        (await PathOf(renamed.Id)).ShouldBe("lab/root/server");
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
        await _vault.DidNotReceiveWithAnyArgs().MergeAsync(default!, default!, default!, default!, default!, default, default);
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

    [Fact]
    public async Task Backup_WritesEveryCertificate_WithItsLatestCrl_AndKeysWhenAsked()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root", withKey: true);
        var issuing = await AddCaAsync(td, "Issuing", root);
        await AddIssuedAsync(issuing, "client", withKey: true);
        await AddIssuedAsync(issuing, "from csr");
        await AddCrlAsync(root, 1, [1]);
        await AddCrlAsync(root, 2, [2]);
        var other = await AddTrustDomainAsync("Other", "team-a", backup: true);
        await AddCaAsync(other, "Elsewhere");

        (await Service(KeyCustodian).PlanBackupAsync(td, new(IncludeKeys: true))).CrlCount.ShouldBe(0);
        var plan = await Service(KeyCustodian).PlanBackupAsync(td, new(IncludeKeys: true, IncludeCrls: true));
        plan.CertificateCount.ShouldBe(4);
        plan.KeyCount.ShouldBe(2);
        plan.CrlCount.ShouldBe(1);
        plan.CertificateOnly.ShouldBe(["Issuing", "from csr"], ignoreOrder: true);

        var progress = new List<int>();
        var result = await Service(KeyCustodian).BackupAsync(td, Token, new(IncludeKeys: true, IncludeCrls: true), progress: new SyncProgress(progress));

        result.SecretsWritten.ShouldBe(4);
        result.Failures.ShouldBeEmpty();
        result.Root.ShouldBe("team-a/lab");
        progress.ShouldBe([1, 2, 3, 4]);
        var writes = _writes.ToDictionary(w => w.Path, w => w.Fields);
        writes.Keys.ShouldBe(["team-a/lab/root", "team-a/lab/root/issuing", "team-a/lab/root/issuing/client", "team-a/lab/root/issuing/from-csr"], ignoreOrder: true);
        writes["team-a/lab/root"].Keys.ShouldBe(["Root.cer", "Root.p12", "password", "Root.crl"], ignoreOrder: true);
        writes["team-a/lab/root"]["Root.crl"].ShouldBe(Convert.ToBase64String([2]));
        writes["team-a/lab/root"]["password"].ShouldBe("ca-pass");
        writes["team-a/lab/root/issuing/client"].Keys.ShouldBe(["client.cer", "client.p12", "password"], ignoreOrder: true);
        writes["team-a/lab/root/issuing/from-csr"].Keys.ShouldBe(["from csr.cer"]);

        var saved = (await Service(Auditor).GetTrustDomainVaultSettingsAsync()).Single(t => t.TrustDomainId == td);
        saved.LastBackupBy.ShouldNotBeNull();
        saved.LastBackupAt.ShouldNotBeNull();
    }

    [Fact]
    public async Task Backup_ChainInP12_WritesChainP12sBelowTheRoot()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root", withKey: true);
        var issuing = await AddCaAsync(td, "Issuing", root);
        await AddIssuedAsync(issuing, "client", withKey: true);

        await Service(KeyCustodian).BackupAsync(td, Token, new(IncludeKeys: true, ChainInP12: true));

        var writes = _writes.ToDictionary(w => w.Path, w => w.Fields);
        writes["team-a/lab/root"].Keys.ShouldBe(["Root.cer", "Root.p12", "password"], ignoreOrder: true);
        var client = writes["team-a/lab/root/issuing/client"];
        client.Keys.ShouldBe(["client.cer", "client-chain.p12", "password"], ignoreOrder: true);
        var p12 = X509CertificateLoader.LoadPkcs12Collection(Convert.FromBase64String(client["client-chain.p12"]), client["password"]);
        p12.Select(c => c.Subject).ShouldBe(["CN=client", "CN=Issuing", "CN=Root"], ignoreOrder: true);
    }

    [Fact]
    public async Task Backup_LeavesOutExcludedCertificates_AndTheirWholeRenewalLineage()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "server");
        var renewal = await AddIssuedAsync(root, "server", renewalOf: first.Id);
        await AddIssuedAsync(root, "client");

        await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => Service(Auditor).SetBackupExcludedAsync("IssuedCertificate", first.Id, true));
        await Service(CaOperator).SetBackupExcludedAsync("IssuedCertificate", first.Id, true);

        // The renewal is excluded with it, and so is a later renewal.
        (await Service(Auditor).IsBackupExcludedAsync("IssuedCertificate", renewal.Id)).ShouldBeTrue();
        var third = await AddIssuedAsync(root, "server", renewalOf: renewal.Id);
        (await Service(Auditor).IsBackupExcludedAsync("IssuedCertificate", third.Id)).ShouldBeTrue();

        var plan = await Service(CaOperator).PlanBackupAsync(td, new());
        plan.Excluded.ShouldBe(["server"]);
        plan.Superseded.ShouldBeEmpty();
        plan.Secrets.Select(s => s.RelativePath).ShouldBe(["lab/root", "lab/root/client"], ignoreOrder: true);

        await Service(CaOperator).SetBackupExcludedAsync("IssuedCertificate", third.Id, false);
        (await Service(CaOperator).PlanBackupAsync(td, new())).Excluded.ShouldBeEmpty();
    }

    [Fact]
    public async Task Backup_ExcludingACa_LeavesItsOwnSecretOut_ButKeepsWhatItIssued()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var issuing = await AddCaAsync(td, "Issuing", root);
        await AddIssuedAsync(issuing, "client");

        await Service(CaOperator).SetBackupExcludedAsync("CaCertificate", issuing, true);
        await Service(CaOperator).BackupAsync(td, Token, new());

        _writes.Select(w => w.Path).ShouldBe(["team-a/lab/root", "team-a/lab/root/issuing/client"], ignoreOrder: true);
    }

    [Fact]
    public async Task ARenewalOfAnExportedCertificate_IsPending_UntilVaultIsUpdated()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "server");
        await AddIssuedAsync(root, "never exported");

        await Service(CaOperator).ExportAsync(new("IssuedCertificate", first.Id, VaultExportArtifact.Cer), Token);
        (await Service(Auditor).GetPendingUpdatesAsync(td)).ShouldBeEmpty();

        var renewal = await AddIssuedAsync(root, "server (renewed)", renewalOf: first.Id);
        var pending = (await Service(Auditor).GetPendingUpdatesAsync(td)).Single();
        pending.ShouldBe(new VaultPendingUpdate("lab/root/server", "server (renewed)", "server", "IssuedCertificate", renewal.Id));

        _existing["team-a/lab/root/server"] = ["server.cer", "note"];
        var result = await Service(CaOperator).UpdateAsync(td, Token);

        result.Updated.ShouldBe(["team-a/lab/root/server"]);
        _writes[^1].Fields.Keys.ShouldBe(["server (renewed).cer"]);
        _removes[^1].Removed.ShouldBe(["server.cer"]);
        (await Service(Auditor).GetPendingUpdatesAsync(td)).ShouldBeEmpty();
    }

    [Fact]
    public async Task Update_RefreshesTheP12KindsTheSecretHolds_ForAKeyCustodian()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var issuing = await AddCaAsync(td, "Issuing", root);
        var first = await AddIssuedAsync(issuing, "client", withKey: true);
        await Service(KeyCustodian).ExportAsync(new("IssuedCertificate", first.Id, VaultExportArtifact.P12WithChain), Token);
        await AddIssuedAsync(issuing, "client", withKey: true, renewalOf: first.Id);
        _existing["team-a/lab/root/issuing/client"] = ["client.cer", "client-chain.p12", "password"];

        var result = await Service(KeyCustodian).UpdateAsync(td, Token);

        result.Notes.ShouldBeEmpty();
        _writes[^1].Fields.Keys.ShouldBe(["client.cer", "client-chain.p12", "password"], ignoreOrder: true);
        _removes[^1].Removed.ShouldBeEmpty();
    }

    [Fact]
    public async Task Update_WithoutExportKeys_LeavesTheP12FilesAndSaysSo()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "client", withKey: true);
        await Service(KeyCustodian).ExportAsync(new("IssuedCertificate", first.Id, VaultExportArtifact.P12), Token);
        await AddIssuedAsync(root, "client v2", withKey: true, renewalOf: first.Id);
        _existing["team-a/lab/root/client"] = ["client.cer", "client.p12", "password"];

        var result = await Service(CaOperator).UpdateAsync(td, Token);

        result.Notes.Single().ShouldContain("KeyCustodian");
        _writes[^1].Fields.Keys.ShouldBe(["client v2.cer"]);
        _removes[^1].Removed.ShouldBe(["client.cer"]);
    }

    [Fact]
    public async Task NothingIsPending_WhenBackupIsOff_OrTheCertificateIsLeftOut()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "server");
        await Service(CaOperator).ExportAsync(new("IssuedCertificate", first.Id, VaultExportArtifact.Cer), Token);
        await AddIssuedAsync(root, "server", renewalOf: first.Id);
        (await Service(Auditor).GetPendingUpdatesAsync(td)).Count.ShouldBe(1);

        await Service(CaOperator).SetBackupExcludedAsync("IssuedCertificate", first.Id, true);
        (await Service(Auditor).GetPendingUpdatesAsync(td)).ShouldBeEmpty();

        await Service(CaOperator).SetBackupExcludedAsync("IssuedCertificate", first.Id, false);
        await Service(Admin).SetTrustDomainBackupAsync(td, false);
        (await Service(Auditor).GetPendingUpdatesAsync(td)).ShouldBeEmpty();
        await Should.ThrowAsync<InvalidOperationException>(() => Service(CaOperator).UpdateAsync(td, Token));
    }

    [Fact]
    public async Task ABackupCountsAsAnExport_ForLaterRenewals()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "server");

        await Service(CaOperator).BackupAsync(td, Token, new());
        await AddIssuedAsync(root, "server", renewalOf: first.Id);

        (await Service(Auditor).GetPendingUpdatesAsync(td)).Single().Name.ShouldBe("server");
        _vault.ReadFieldNamesAsync(default!, default!, default!, default!, default)
            .ReturnsForAnyArgs<IReadOnlyCollection<string>>(_ => throw new VaultTokenRefusedException("x", 403));
        await Should.ThrowAsync<VaultTokenRefusedException>(() => Service(CaOperator).UpdateAsync(td, Token));
        (await Service(Auditor).GetPendingUpdatesAsync(td)).Count.ShouldBe(1);
    }

    [Fact]
    public async Task Backup_WithoutKeys_IsOpenToCaOperators_ButKeysNeedAKeyCustodian()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root", withKey: true);
        await AddIssuedAsync(root, "client", withKey: true);

        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(CaOperator).BackupAsync(td, Token, new(IncludeKeys: true)));
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(Auditor).BackupAsync(td, Token, new()));
        _writes.ShouldBeEmpty();

        var result = await Service(CaOperator).BackupAsync(td, Token, new());

        result.SecretsWritten.ShouldBe(2);
        _writes.SelectMany(w => w.Fields.Keys).ShouldBe(["Root.cer", "client.cer"], ignoreOrder: true);
    }

    [Fact]
    public async Task Backup_IsRefusedUntilAnAdminTurnsItOnForTheTrustDomain()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a");
        await AddCaAsync(td, "Root");

        await Should.ThrowAsync<InvalidOperationException>(() => Service(CaOperator).PlanBackupAsync(td, new()));
        await Should.ThrowAsync<InvalidOperationException>(() => Service(CaOperator).BackupAsync(td, Token, new()));
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => Service(CaOperator).SetTrustDomainBackupAsync(td, true));

        await Service(Admin).SetTrustDomainBackupAsync(td, true);

        (await Service(CaOperator).BackupAsync(td, Token, new())).SecretsWritten.ShouldBe(1);
        (await Service(Auditor).GetTrustDomainVaultSettingsAsync()).Single().BackupEnabled.ShouldBeTrue();
    }

    [Fact]
    public async Task Backup_WritesTheNewestGenerationOfARenewal()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", "team-a", backup: true);
        var root = await AddCaAsync(td, "Root");
        var first = await AddIssuedAsync(root, "server");
        var renewal = await AddIssuedAsync(root, "server", renewalOf: first.Id);

        var plan = await Service(CaOperator).PlanBackupAsync(td, new());

        plan.Secrets.Single(s => s.RelativePath == "lab/root/server").Targets.Single().Id.ShouldBe(renewal.Id);
        plan.Superseded.ShouldBe(["server (lab/root/server)"]);
    }

    [Fact]
    public async Task Backup_SetsTheFirstNamespace_ReportsAFailedSecret_AndCarriesOn()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", ns: null, backup: true);
        var root = await AddCaAsync(td, "Root");
        await AddIssuedAsync(root, "a");
        await AddIssuedAsync(root, "b");
        _vault.MergeAsync(default!, default!, default!, default!, default!, default, default)
            .ReturnsForAnyArgs(call =>
            {
                var path = call.ArgAt<string>(3);
                if (path.EndsWith("/a")) throw new HttpRequestException("Vault answered HTTP 500");
                _writes.Add((path, call.ArgAt<IReadOnlyDictionary<string, string>>(4)));
                return 1;
            });

        await Should.ThrowAsync<ArgumentException>(() => Service(CaOperator).BackupAsync(td, Token, new()));
        var result = await Service(CaOperator).BackupAsync(td, Token, new(), firstNamespace: "team-b");

        result.SecretsWritten.ShouldBe(2);
        result.Failures.Single().ShouldStartWith("team-b/lab/root/a:");
        (await Service(Auditor).GetTrustDomainVaultSettingsAsync()).Single().Namespace.ShouldBe("team-b");
    }

    [Fact]
    public async Task Backup_StopsWhenVaultRefusesTheToken()
    {
        await EnableAsync();
        var td = await AddTrustDomainAsync("Lab", ns: null, backup: true);
        await AddCaAsync(td, "Root");
        _vault.MergeAsync(default!, default!, default!, default!, default!, default, default)
            .ReturnsForAnyArgs<int>(_ => throw new VaultTokenRefusedException("team-b/lab/root", 403));

        await Should.ThrowAsync<VaultTokenRefusedException>(() => Service(CaOperator).BackupAsync(td, Token, new(), "team-b"));

        var saved = (await Service(Auditor).GetTrustDomainVaultSettingsAsync()).Single();
        saved.Namespace.ShouldBeNull();
        saved.LastBackupAt.ShouldBeNull();
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

    private async Task<int> AddTrustDomainAsync(string name, string? ns, bool backup = false)
    {
        await using var db = _dbFactory.CreateDbContext();
        var td = new TrustDomain { Name = name, VaultNamespace = ns, VaultBackupEnabled = backup };
        db.TrustDomains.Add(td);
        await db.SaveChangesAsync();
        return td.Id;
    }

    private async Task<int> AddCaAsync(int trustDomainId, string name, int? parentId = null, bool withKey = false)
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
            EncryptedPfxBytes = withKey ? cert.Export(X509ContentType.Pkcs12, "ca-pass") : null,
            PfxPassword = withKey ? "ca-pass" : null,
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

    private async Task AddCrlAsync(int caId, long number, byte[] bytes)
    {
        await using var db = _dbFactory.CreateDbContext();
        db.Crls.Add(new Crl { CaCertificateId = caId, CrlNumber = number, RawBytes = bytes, FileName = $"crl-{number}.crl" });
        await db.SaveChangesAsync();
    }

    /// <summary>Reports synchronously, unlike <see cref="Progress{T}"/>, so the test sees every value.</summary>
    private sealed class SyncProgress(List<int> values) : IProgress<int>
    {
        public void Report(int value) => values.Add(value);
    }
}
