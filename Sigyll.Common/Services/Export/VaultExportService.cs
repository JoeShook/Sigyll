#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;

namespace Sigyll.Common.Services.Export;

/// <summary>What to export: the same files the download buttons produce.</summary>
public enum VaultExportArtifact
{
    /// <summary>The public certificate, PEM (what the .cer download holds).</summary>
    Cer,
    /// <summary>Certificate and private key, PKCS#12.</summary>
    P12,
    /// <summary>Certificate and private key plus the issuing CA certificates, PKCS#12.</summary>
    P12WithChain,
    /// <summary>A CRL, DER; it goes into its CA's secret.</summary>
    Crl,
}

/// <param name="EntityType">"CaCertificate", "IssuedCertificate" or "Crl".</param>
public record VaultExportTarget(string EntityType, int Id, VaultExportArtifact Artifact);

/// <summary>What a full backup adds besides each certificate's .cer.</summary>
/// <param name="IncludeKeys">The P12 files (and their password) of certificates whose key Sigyll holds.</param>
/// <param name="ChainInP12">Write each P12 below a root with its issuing CA certificates, as <c>name-chain.p12</c>,
/// instead of <c>name.p12</c>.</param>
/// <param name="IncludeCrls">Each CA's latest CRL, in the CA's secret.</param>
public record VaultBackupOptions(bool IncludeKeys = false, bool ChainInP12 = false, bool IncludeCrls = false);

/// <summary>Where an export would go, shown to the operator before they confirm it.</summary>
/// <param name="Namespace">The trust domain's folder under the mount; null until the first export sets it.</param>
/// <param name="RelativePath">The secret's path below the namespace: trust domain, then the CA hierarchy.</param>
/// <param name="Fields">The secret's fields the export writes.</param>
public record VaultExportPlan(
    int TrustDomainId,
    string TrustDomainName,
    string? Namespace,
    string Address,
    string Mount,
    string RelativePath,
    IReadOnlyList<string> Fields)
{
    public string PathFor(string ns) => $"{ns}/{RelativePath}";
}

public record VaultExportResult(string Address, string Mount, string Path, int Version, IReadOnlyList<string> Fields);

public record TrustDomainVaultSettings(
    int TrustDomainId,
    string TrustDomainName,
    string? Namespace,
    bool BackupEnabled,
    DateTime? LastBackupAt,
    string? LastBackupBy);

/// <summary>One secret a full backup writes: a certificate's files, at the path a single export would use.</summary>
/// <param name="Name">The certificate's name.</param>
public record VaultBackupSecret(string RelativePath, string Name, IReadOnlyList<VaultExportTarget> Targets, IReadOnlyList<string> Fields);

/// <summary>What a full backup of a trust domain would write, shown before the operator runs it.</summary>
/// <param name="CertificateOnly">Certificates whose private key Sigyll doesn't hold (an HSM, Vault Transit or KMS key,
/// or a certificate issued from a CSR): only their .cer is backed up.</param>
/// <param name="Superseded">Earlier generations of renewed certificates. They share their renewal's secret, which holds
/// the newest generation; Vault's version history keeps what earlier exports wrote.</param>
/// <param name="Excluded">Certificates an operator left out of the backup.</param>
public record VaultBackupPlan(
    int TrustDomainId,
    string TrustDomainName,
    string? Namespace,
    string Address,
    string Mount,
    VaultBackupOptions Options,
    IReadOnlyList<VaultBackupSecret> Secrets,
    IReadOnlyList<string> CertificateOnly,
    IReadOnlyList<string> Superseded,
    IReadOnlyList<string> Excluded)
{
    public int CertificateCount => Secrets.Count;
    public int KeyCount => Secrets.Sum(s => s.Targets.Count(t => t.Artifact is VaultExportArtifact.P12 or VaultExportArtifact.P12WithChain));
    public int CrlCount => Secrets.Sum(s => s.Targets.Count(t => t.Artifact == VaultExportArtifact.Crl));
}

/// <summary>A certificate in Vault that was renewed or rekeyed since: its secret still holds an earlier generation.</summary>
/// <param name="PreviousName">The name of the generation Vault last got.</param>
public record VaultPendingUpdate(string RelativePath, string Name, string? PreviousName, string EntityType, int Id);

/// <param name="Updated">The secrets written.</param>
/// <param name="Notes">Secrets written with a caveat, e.g. P12 files left as they were.</param>
/// <param name="Failures">Secrets that weren't written, with the reason.</param>
public record VaultUpdateResult(string Address, string Mount, IReadOnlyList<string> Updated, IReadOnlyList<string> Notes, IReadOnlyList<string> Failures);

/// <param name="Root">The trust domain's folder: <c>&lt;namespace&gt;/&lt;trust domain&gt;</c>.</param>
/// <param name="Failures">Secrets that weren't written, with the reason.</param>
public record VaultBackupResult(string Address, string Mount, string Root, int SecretsWritten, int SecretsPlanned, IReadOnlyList<string> Failures);

/// <summary>
/// Exports certificate files to a HashiCorp Vault KV v2 mount instead of (or as well as) downloading them. The
/// secret path mirrors the trust domain's hierarchy: <c>&lt;namespace&gt;/&lt;trust domain&gt;/&lt;root&gt;/…/&lt;certificate&gt;</c>,
/// one secret per certificate, with fields named like the downloaded files. The operator's own Vault token does
/// the writing, so Vault's policies apply to them; Sigyll never stores it.
/// </summary>
public partial class VaultExportService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IOperatorContext _operator;
    private readonly CertificateExportService _exportService;
    private readonly IVaultKvClient _vault;
    private readonly ILogger<VaultExportService> _logger;

    public VaultExportService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        IOperatorContext operatorContext,
        CertificateExportService exportService,
        IVaultKvClient vault,
        ILogger<VaultExportService> logger)
    {
        _dbFactory = dbFactory;
        _operator = operatorContext;
        _exportService = exportService;
        _vault = vault;
        _logger = logger;
    }

    public async Task<VaultExportSettings> GetSettingsAsync(CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.VaultExportSettings.AsNoTracking().SingleOrDefaultAsync(ct) ?? new VaultExportSettings();
    }

    public async Task<VaultExportSettings> SaveSettingsAsync(bool enabled, string? address, string? mount, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Administer);

        address = string.IsNullOrWhiteSpace(address) ? null : address.Trim().TrimEnd('/');
        if (address != null && !(Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http"))
            throw new ArgumentException("The Vault address must be an http(s) URL, e.g. https://vault.example.org:8200.");
        if (enabled && address == null)
            throw new ArgumentException("Set the Vault address before enabling export to Vault.");
        var normalizedMount = NormalizeFolder(mount)
            ?? throw new ArgumentException("Set the KV v2 mount, e.g. secret.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await db.VaultExportSettings.SingleOrDefaultAsync(ct);
        if (settings == null)
        {
            settings = new VaultExportSettings();
            db.VaultExportSettings.Add(settings);
        }
        settings.Enabled = enabled;
        settings.Address = address;
        settings.Mount = normalizedMount;
        settings.UpdatedAt = DateTime.UtcNow;
        settings.UpdatedBy = identity.Name;
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("{Actor} set export to Vault {State}: {Address}, mount {Mount}",
            identity.Name, enabled ? "on" : "off", address, normalizedMount);
        return settings;
    }

    public async Task<List<TrustDomainVaultSettings>> GetTrustDomainVaultSettingsAsync(CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.TrustDomains
            .OrderBy(t => t.Name)
            .Select(t => new TrustDomainVaultSettings(t.Id, t.Name, t.VaultNamespace, t.VaultBackupEnabled, t.VaultLastBackupAt, t.VaultLastBackupBy))
            .ToListAsync(ct);
    }

    /// <summary>Turns full backup to Vault on or off for a trust domain.</summary>
    public async Task SetTrustDomainBackupAsync(int trustDomainId, bool enabled, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Administer);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var trustDomain = await db.TrustDomains.FindAsync([trustDomainId], ct)
            ?? throw new ArgumentException("Trust domain not found.");
        if (trustDomain.VaultBackupEnabled == enabled) return;

        trustDomain.VaultBackupEnabled = enabled;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{Actor} turned full backup to Vault {State} for trust domain {TrustDomain}",
            identity.Name, enabled ? "on" : "off", trustDomain.Name);
    }

    /// <summary>Changes (or clears) a trust domain's namespace. Only an Admin can redirect where keys go.</summary>
    public async Task SetTrustDomainNamespaceAsync(int trustDomainId, string? ns, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Administer);

        var normalized = string.IsNullOrWhiteSpace(ns)
            ? null
            : NormalizeFolder(ns) ?? throw new ArgumentException(InvalidNamespaceMessage);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var trustDomain = await db.TrustDomains.FindAsync([trustDomainId], ct)
            ?? throw new ArgumentException("Trust domain not found.");
        if (trustDomain.VaultNamespace == normalized) return;

        _logger.LogInformation("{Actor} changed the Vault namespace of trust domain {TrustDomain} from {Old} to {New}",
            identity.Name, trustDomain.Name, trustDomain.VaultNamespace ?? "(none)", normalized ?? "(none)");
        trustDomain.VaultNamespace = normalized;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Where <paramref name="target"/> would be exported, and which fields it would write.</summary>
    public async Task<VaultExportPlan> PlanAsync(VaultExportTarget target, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await RequireEnabledAsync(db, ct);
        return await BuildPlanAsync(db, settings, target, ct);
    }

    /// <summary>
    /// The folders at the top of the mount that <paramref name="token"/> can see, to pick a namespace from. Empty
    /// when the token may not list the mount (many policies allow writing a path but not listing its parent).
    /// </summary>
    public async Task<IReadOnlyList<string>> ListNamespacesAsync(string token, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.Operate, Permission.ExportKeys);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await RequireEnabledAsync(db, ct);
        try
        {
            var keys = await _vault.ListAsync(new Uri(settings.Address!), token, settings.Mount, "", ct);
            return keys.Where(k => k.EndsWith('/')).Select(k => k.TrimEnd('/')).Order().ToList();
        }
        catch (VaultTokenRefusedException)
        {
            return [];
        }
    }

    /// <summary>
    /// Writes <paramref name="target"/> to Vault with the operator's <paramref name="token"/>. When the trust domain
    /// has no namespace yet, <paramref name="firstNamespace"/> sets it; after that, only an Admin can change it.
    /// </summary>
    public async Task<VaultExportResult> ExportAsync(
        VaultExportTarget target, string token, string? firstNamespace = null, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Operate, Permission.ExportKeys);
        if (target.Artifact is VaultExportArtifact.P12 or VaultExportArtifact.P12WithChain)
            await _operator.DemandAsync(Permission.ExportKeys);

        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Paste a Vault token to export.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await RequireEnabledAsync(db, ct);
        var plan = await BuildPlanAsync(db, settings, target, ct);

        var (ns, settingNamespace) = ResolveNamespace(plan.TrustDomainName, plan.Namespace, firstNamespace);

        var fields = await BuildFieldsAsync(db, target, ct);
        var path = plan.PathFor(ns);
        var version = await _vault.MergeAsync(new Uri(settings.Address!), token.Trim(), settings.Mount, path, fields, ct: ct);

        if (settingNamespace)
            await SaveFirstNamespaceAsync(db, plan.TrustDomainId, ns, identity.Name, ct);
        await MarkExportedAsync(db, target, ct);

        _logger.LogInformation(
            "{Actor} exported {Fields} of {EntityType} {Id} to Vault {Address} {Mount}/{Path} (version {Version})",
            identity.Name, string.Join(", ", fields.Keys), target.EntityType, target.Id, settings.Address, settings.Mount, path, version);

        return new VaultExportResult(settings.Address!, settings.Mount, path, version, fields.Keys.ToList());
    }

    /// <summary>
    /// What a full backup of the trust domain would write: one secret per certificate (the newest generation of a
    /// renewed one), with its .cer and what <paramref name="options"/> add.
    /// </summary>
    public async Task<VaultBackupPlan> PlanBackupAsync(int trustDomainId, VaultBackupOptions options, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await RequireEnabledAsync(db, ct);
        return await BuildBackupPlanAsync(db, settings, trustDomainId, options, ct);
    }

    /// <summary>
    /// Writes every secret of <see cref="PlanBackupAsync"/> with the operator's <paramref name="token"/>. A secret that
    /// fails is reported and the backup carries on; a refused token stops it. Backing up keys takes the ExportKeys
    /// permission, like downloading one.
    /// </summary>
    /// <param name="progress">Receives the number of secrets done so far.</param>
    public async Task<VaultBackupResult> BackupAsync(
        int trustDomainId, string token, VaultBackupOptions options, string? firstNamespace = null,
        IProgress<int>? progress = null, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Operate, Permission.ExportKeys);
        if (options.IncludeKeys)
            await _operator.DemandAsync(Permission.ExportKeys);

        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Paste a Vault token to back up.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await RequireEnabledAsync(db, ct);
        var plan = await BuildBackupPlanAsync(db, settings, trustDomainId, options, ct);
        var (ns, settingNamespace) = ResolveNamespace(plan.TrustDomainName, plan.Namespace, firstNamespace);

        var address = new Uri(settings.Address!);
        var written = 0;
        var failures = new List<string>();
        foreach (var secret in plan.Secrets)
        {
            var path = $"{ns}/{secret.RelativePath}";
            try
            {
                var fields = new Dictionary<string, string>();
                foreach (var target in secret.Targets)
                foreach (var (name, value) in await BuildFieldsAsync(db, target, ct))
                    fields[name] = value;

                await _vault.MergeAsync(address, token.Trim(), settings.Mount, path, fields, ct: ct);
                if (written++ == 0 && settingNamespace)
                    await SaveFirstNamespaceAsync(db, plan.TrustDomainId, ns, identity.Name, ct);
                await MarkExportedAsync(db, secret.Targets[0], ct);
            }
            catch (VaultTokenRefusedException) when (written == 0)
            {
                throw;
            }
            catch (VaultTokenRefusedException ex)
            {
                failures.Add($"{path}: {ex.Message} The backup stopped here.");
                break;
            }
            catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                failures.Add($"{path}: {ex.Message}");
            }
            progress?.Report(written + failures.Count);
        }

        if (written > 0)
        {
            var trustDomain = await db.TrustDomains.FindAsync([plan.TrustDomainId], ct);
            trustDomain!.VaultLastBackupAt = DateTime.UtcNow;
            trustDomain.VaultLastBackupBy = identity.Name;
            await db.SaveChangesAsync(ct);
        }

        var root = $"{ns}/{Slug(plan.TrustDomainName)}";
        _logger.LogInformation(
            "{Actor} backed up trust domain {TrustDomain} to Vault {Address} {Mount}/{Root}: {Written} of {Planned} secrets, keys {Keys}, CRLs {Crls}, {Failed} failed",
            identity.Name, plan.TrustDomainName, settings.Address, settings.Mount, root, written, plan.Secrets.Count,
            options.IncludeKeys ? (options.ChainInP12 ? "included with chains" : "included") : "left out",
            options.IncludeCrls ? "included" : "left out", failures.Count);

        return new VaultBackupResult(settings.Address!, settings.Mount, root, written, plan.Secrets.Count, failures);
    }

    /// <summary>
    /// Whether the full backup leaves the certificate out. The setting covers its whole renewal lineage, since every
    /// generation shares one secret.
    /// </summary>
    public async Task<bool> IsBackupExcludedAsync(string entityType, int id, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return (await LineageAsync(db, entityType, id, ct)).Any(n => n.Excluded);
    }

    /// <summary>Leaves the certificate, and every generation of its renewal lineage, out of the full backup (or not).</summary>
    public async Task SetBackupExcludedAsync(string entityType, int id, bool excluded, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Operate);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var ids = (await LineageAsync(db, entityType, id, ct)).Select(n => n.Id).ToList();
        if (entityType == "CaCertificate")
            foreach (var ca in await db.CaCertificates.Where(c => ids.Contains(c.Id)).ToListAsync(ct))
                ca.VaultBackupExcluded = excluded;
        else
            foreach (var issued in await db.IssuedCertificates.Where(c => ids.Contains(c.Id)).ToListAsync(ct))
                issued.VaultBackupExcluded = excluded;
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("{Actor} {Action} the full backup to Vault: {EntityType} {Ids}",
            identity.Name, excluded ? "left out of" : "put back into", entityType, string.Join(", ", ids));
    }

    private sealed record LineageNode(int Id, int? RenewalOfId, bool Excluded);

    /// <summary>The certificate and every certificate linked to it by renewal, in either direction.</summary>
    private static async Task<List<LineageNode>> LineageAsync(SigyllDbContext db, string entityType, int id, CancellationToken ct)
    {
        var all = entityType switch
        {
            "CaCertificate" => await db.CaCertificates.AsNoTracking()
                .Select(c => new LineageNode(c.Id, c.RenewalOfId, c.VaultBackupExcluded)).ToListAsync(ct),
            "IssuedCertificate" => await db.IssuedCertificates.AsNoTracking()
                .Select(c => new LineageNode(c.Id, c.RenewalOfId, c.VaultBackupExcluded)).ToListAsync(ct),
            _ => throw new ArgumentException($"Unknown entity type {entityType}."),
        };
        if (all.All(n => n.Id != id))
            throw new ArgumentException("Certificate not found.");

        var renewals = all.Where(n => n.RenewalOfId != null).ToLookup(n => n.RenewalOfId!.Value);
        var byId = all.ToDictionary(n => n.Id);
        var found = new Dictionary<int, LineageNode>();
        var pending = new Stack<int>([id]);
        while (pending.TryPop(out var next))
        {
            if (!byId.TryGetValue(next, out var node) || !found.TryAdd(next, node)) continue;
            if (node.RenewalOfId is int previous) pending.Push(previous);
            foreach (var renewal in renewals[next]) pending.Push(renewal.Id);
        }
        return found.Values.ToList();
    }

    /// <summary>
    /// Certificates in Vault that changed since: an earlier generation was exported, backed up or updated, but the
    /// newest wasn't. Empty unless export to Vault and the trust domain's full backup are on.
    /// </summary>
    public async Task<IReadOnlyList<VaultPendingUpdate>> GetPendingUpdatesAsync(int trustDomainId, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await db.VaultExportSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        if (settings is not { Enabled: true, Address: not null })
            return [];
        var (trustDomain, groups, _) = await LoadSecretsAsync(db, trustDomainId, ct);
        if (!trustDomain.VaultBackupEnabled || trustDomain.VaultNamespace == null)
            return [];

        return groups.Where(g => g.NeedsUpdate)
            .Select(g => new VaultPendingUpdate(g.Path, g.Newest.Node.Name,
                g.Generations.LastOrDefault(x => x.ExportedAt != null)?.Node.Name, g.Newest.EntityType, g.Newest.Node.Id))
            .ToList();
    }

    /// <summary>
    /// Writes the newest generation of each <see cref="GetPendingUpdatesAsync">changed certificate</see> to its secret,
    /// with the same kinds of files the secret holds: .cer, and P12, chain P12 and CRL where it has them. The earlier
    /// generation's files are removed. Refreshing P12 files takes ExportKeys; without it they're left as they were.
    /// </summary>
    /// <param name="progress">Receives the number of secrets done so far.</param>
    public async Task<VaultUpdateResult> UpdateAsync(
        int trustDomainId, string token, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        var identity = await _operator.DemandAsync(Permission.Operate, Permission.ExportKeys);

        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("Paste a Vault token to update Vault.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var settings = await RequireEnabledAsync(db, ct);
        var (trustDomain, groups, latestCrls) = await LoadSecretsAsync(db, trustDomainId, ct);
        if (!trustDomain.VaultBackupEnabled)
            throw new InvalidOperationException(
                $"Full backup to Vault is off for trust domain {trustDomain.Name}. An Admin can turn it on in Settings.");
        var ns = trustDomain.VaultNamespace ?? throw new InvalidOperationException(
            $"Trust domain {trustDomain.Name} has no Vault namespace yet; export a certificate to choose one.");

        var address = new Uri(settings.Address!);
        token = token.Trim();
        var updated = new List<string>();
        var notes = new List<string>();
        var failures = new List<string>();
        foreach (var group in groups.Where(g => g.NeedsUpdate))
        {
            var path = $"{ns}/{group.Path}";
            try
            {
                var existing = await _vault.ReadFieldNamesAsync(address, token, settings.Mount, path, ct);
                var (targets, keep, note) = UpdateTargets(group, existing, identity.Has(Permission.ExportKeys), latestCrls);

                var fields = new Dictionary<string, string>();
                foreach (var target in targets)
                foreach (var (name, value) in await BuildFieldsAsync(db, target, ct))
                    fields[name] = value;
                var remove = existing
                    .Where(f => (IsFileField(f) || f == PasswordField) && !fields.ContainsKey(f) && !keep.Contains(f))
                    .ToList();

                await _vault.MergeAsync(address, token, settings.Mount, path, fields, remove, ct);
                await MarkExportedAsync(db, targets[0], ct);
                updated.Add(path);
                if (note != null)
                    notes.Add($"{path}: {note}");
            }
            catch (VaultTokenRefusedException) when (updated.Count == 0 && failures.Count == 0)
            {
                throw;
            }
            catch (VaultTokenRefusedException ex)
            {
                failures.Add($"{path}: {ex.Message} The update stopped here.");
                break;
            }
            catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                failures.Add($"{path}: {ex.Message}");
            }
            progress?.Report(updated.Count + failures.Count);
        }

        _logger.LogInformation(
            "{Actor} updated {Count} changed certificates of trust domain {TrustDomain} in Vault {Address} {Mount}: {Paths}; {Failed} failed",
            identity.Name, updated.Count, trustDomain.Name, settings.Address, settings.Mount, string.Join(", ", updated), failures.Count);

        return new VaultUpdateResult(settings.Address!, settings.Mount, updated, notes, failures);
    }

    /// <summary>
    /// What to write for the newest generation of <paramref name="group"/>, mirroring the files its secret holds;
    /// <c>Keep</c> lists existing fields to leave in place rather than remove.
    /// </summary>
    private static (List<VaultExportTarget> Targets, HashSet<string> Keep, string? Note) UpdateTargets(
        SecretGroup group, IReadOnlyCollection<string> existing, bool canExportKeys, Dictionary<int, int> latestCrls)
    {
        var newest = group.Newest;
        var targets = new List<VaultExportTarget> { new(newest.EntityType, newest.Node.Id, VaultExportArtifact.Cer) };
        var keep = new HashSet<string>();
        string? note = null;

        var hadChainP12 = existing.Any(f => f.EndsWith("-chain.p12", StringComparison.Ordinal));
        var hadP12 = existing.Any(f => f.EndsWith(".p12", StringComparison.Ordinal) && !f.EndsWith("-chain.p12", StringComparison.Ordinal));
        if (hadChainP12 || hadP12)
        {
            if (!newest.HasKey)
                note = "Sigyll doesn't hold the new generation's key, so the earlier P12 files were removed.";
            else if (!canExportKeys)
            {
                keep.UnionWith(existing.Where(f => f.EndsWith(".p12", StringComparison.Ordinal) || f == PasswordField));
                note = "P12 files not refreshed (that needs the KeyCustodian role); they still hold the earlier key.";
            }
            else
            {
                // A root's chain is just itself.
                if (hadChainP12 && newest.Node.ParentId != null)
                    targets.Add(new(newest.EntityType, newest.Node.Id, VaultExportArtifact.P12WithChain));
                if (hadP12 || newest.Node.ParentId == null)
                    targets.Add(new(newest.EntityType, newest.Node.Id, VaultExportArtifact.P12));
            }
        }

        var crlFields = existing.Where(f => f.EndsWith(".crl", StringComparison.Ordinal)).ToList();
        if (newest.IsCa && crlFields.Count > 0)
        {
            if (latestCrls.TryGetValue(newest.Node.Id, out var crlId))
                targets.Add(new("Crl", crlId, VaultExportArtifact.Crl));
            else
                keep.UnionWith(crlFields);
        }

        return (targets, keep, note);
    }

    private static bool IsFileField(string field) =>
        field.EndsWith(".cer", StringComparison.Ordinal)
        || field.EndsWith(".p12", StringComparison.Ordinal)
        || field.EndsWith(".crl", StringComparison.Ordinal);

    /// <summary>Records that the certificate was written to Vault, so a later renewal is offered as an update.</summary>
    private static async Task MarkExportedAsync(SigyllDbContext db, VaultExportTarget target, CancellationToken ct)
    {
        var caId = target.EntityType switch
        {
            "CaCertificate" => target.Id,
            "Crl" => await db.Crls.Where(c => c.Id == target.Id).Select(c => (int?)c.CaCertificateId).SingleOrDefaultAsync(ct),
            _ => (int?)null,
        };
        if (caId is int id)
        {
            if (await db.CaCertificates.FindAsync([id], ct) is { } ca)
                ca.VaultExportedAt = DateTime.UtcNow;
        }
        else if (await db.IssuedCertificates.FindAsync([target.Id], ct) is { } issued)
        {
            issued.VaultExportedAt = DateTime.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// The namespace an export writes to: the trust domain's, or <paramref name="firstNamespace"/> when it has none
    /// yet (then <c>Setting</c> is true). Naming a different one for a mapped trust domain is refused.
    /// </summary>
    private static (string Namespace, bool Setting) ResolveNamespace(string trustDomainName, string? current, string? firstNamespace)
    {
        if (current == null)
            return (NormalizeFolder(firstNamespace)
                ?? throw new ArgumentException($"Choose the Vault namespace for trust domain {trustDomainName}. {InvalidNamespaceMessage}"), true);
        if (!string.IsNullOrWhiteSpace(firstNamespace) && NormalizeFolder(firstNamespace) != current)
            throw new InvalidOperationException(
                $"Trust domain {trustDomainName} already exports to namespace {current}; only an Admin can change it.");
        return (current, false);
    }

    /// <summary>Records the namespace the first export chose, once Vault has accepted a write to it.</summary>
    private async Task SaveFirstNamespaceAsync(SigyllDbContext db, int trustDomainId, string ns, string actor, CancellationToken ct)
    {
        var trustDomain = await db.TrustDomains.FindAsync([trustDomainId], ct);
        if (trustDomain is not { VaultNamespace: null }) return;

        trustDomain.VaultNamespace = ns;
        await db.SaveChangesAsync(ct);
        _logger.LogInformation("{Actor} set the Vault namespace of trust domain {TrustDomain} to {Namespace}",
            actor, trustDomain.Name, ns);
    }

    private const string InvalidNamespaceMessage =
        "A namespace is one or more folder names of letters, digits, '.', '_' or '-', separated by '/', e.g. team-a.";

    private static async Task<VaultExportSettings> RequireEnabledAsync(SigyllDbContext db, CancellationToken ct)
    {
        var settings = await db.VaultExportSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        if (settings is not { Enabled: true, Address: not null })
            throw new InvalidOperationException("Export to Vault is turned off. An Admin can turn it on in Settings.");
        return settings;
    }

    private async Task<VaultExportPlan> BuildPlanAsync(
        SigyllDbContext db, VaultExportSettings settings, VaultExportTarget target, CancellationToken ct)
    {
        // The secret belongs to a certificate: a CRL goes into its CA's secret.
        int caId;
        IssuedCertificate? issued = null;
        switch (target.EntityType)
        {
            case "CaCertificate":
                caId = target.Id;
                break;
            case "IssuedCertificate":
                issued = await db.IssuedCertificates.AsNoTracking().SingleOrDefaultAsync(c => c.Id == target.Id, ct)
                    ?? throw new ArgumentException("Certificate not found.");
                caId = issued.IssuingCaCertificateId;
                break;
            case "Crl":
                if (target.Artifact != VaultExportArtifact.Crl)
                    throw new ArgumentException("A CRL can only be exported as a CRL.");
                caId = await db.Crls.Where(c => c.Id == target.Id).Select(c => (int?)c.CaCertificateId).SingleOrDefaultAsync(ct)
                    ?? throw new ArgumentException("CRL not found.");
                break;
            default:
                throw new ArgumentException($"Unknown entity type {target.EntityType}.");
        }

        var hierarchy = await Hierarchy.LoadAsync(db, ct);
        if (!hierarchy.Cas.TryGetValue(caId, out var ca))
            throw new ArgumentException("Certificate not found.");

        var trustDomain = await db.TrustDomains.AsNoTracking().SingleAsync(t => t.Id == ca.TrustDomainId, ct);
        var issuedNode = issued == null
            ? null
            : new Node(issued.Id, issued.Name, issued.IssuingCaCertificateId, issued.RenewalOfId, issued.SerialNumber, ca.TrustDomainId);
        var relativePath = await hierarchy.RelativePathAsync(trustDomain.Name, ca, issuedNode, ct);

        var name = issued?.Name ?? ca.Name;
        IReadOnlyList<string> fields = target.Artifact switch
        {
            VaultExportArtifact.Cer => [$"{name}.cer"],
            VaultExportArtifact.P12 => [$"{name}.p12", PasswordField],
            VaultExportArtifact.P12WithChain => [$"{name}-chain.p12", PasswordField],
            _ => [$"{ca.Name}.crl"],
        };

        return new VaultExportPlan(trustDomain.Id, trustDomain.Name, trustDomain.VaultNamespace,
            settings.Address!, settings.Mount, relativePath, fields);
    }

    /// <summary>The field holding the password of the secret's P12 files (the certificate's stored key password).</summary>
    public const string PasswordField = "password";

    private async Task<Dictionary<string, string>> BuildFieldsAsync(SigyllDbContext db, VaultExportTarget target, CancellationToken ct)
    {
        switch (target.Artifact)
        {
            case VaultExportArtifact.Cer:
            {
                var cert = target.EntityType == "CaCertificate"
                    ? await db.CaCertificates.Where(c => c.Id == target.Id)
                        .Select(c => new { c.Name, c.X509CertificatePem }).SingleAsync(ct)
                    : await db.IssuedCertificates.Where(c => c.Id == target.Id)
                        .Select(c => new { c.Name, c.X509CertificatePem }).SingleAsync(ct);
                return new() { [$"{cert.Name}.cer"] = cert.X509CertificatePem };
            }
            case VaultExportArtifact.P12:
            case VaultExportArtifact.P12WithChain:
            {
                var pfx = await _exportService.ExportPfxAsync(target.Id, target.EntityType,
                    target.Artifact == VaultExportArtifact.P12WithChain, ct);
                if (!pfx.Success)
                    throw new InvalidOperationException(pfx.Error);
                return new()
                {
                    [pfx.FileName!] = Convert.ToBase64String(pfx.PfxBytes!),
                    [PasswordField] = pfx.Password ?? string.Empty,
                };
            }
            default:
            {
                var crl = await db.Crls.Include(c => c.CaCertificate).AsNoTracking().SingleAsync(c => c.Id == target.Id, ct);
                return new() { [$"{crl.CaCertificate.Name}.crl"] = Convert.ToBase64String(crl.RawBytes) };
            }
        }
    }

    private async Task<VaultBackupPlan> BuildBackupPlanAsync(
        SigyllDbContext db, VaultExportSettings settings, int trustDomainId, VaultBackupOptions options, CancellationToken ct)
    {
        var (trustDomain, groups, latestCrls) = await LoadSecretsAsync(db, trustDomainId, ct);
        if (!trustDomain.VaultBackupEnabled)
            throw new InvalidOperationException(
                $"Full backup to Vault is off for trust domain {trustDomain.Name}. An Admin can turn it on in Settings.");

        var secrets = new List<VaultBackupSecret>();
        var certificateOnly = new List<string>();
        var superseded = new List<string>();
        var excluded = new List<string>();
        foreach (var group in groups)
        {
            // A renewal shares its predecessor's secret: back up the newest generation.
            var newest = group.Newest;
            if (group.Excluded)
            {
                excluded.Add(newest.Node.Name);
                continue;
            }
            superseded.AddRange(group.Generations.Where(g => g != newest).Select(g => $"{g.Node.Name} ({group.Path})"));

            var (node, isCa, entityType) = (newest.Node, newest.IsCa, newest.EntityType);
            var targets = new List<VaultExportTarget> { new(entityType, node.Id, VaultExportArtifact.Cer) };
            var fields = new List<string> { $"{node.Name}.cer" };

            if (!newest.HasKey)
                certificateOnly.Add(node.Name);
            else if (options.IncludeKeys && options.ChainInP12 && node.ParentId != null)
            {
                targets.Add(new(entityType, node.Id, VaultExportArtifact.P12WithChain));
                fields.AddRange([$"{node.Name}-chain.p12", PasswordField]);
            }
            else if (options.IncludeKeys)
            {
                // A root's chain is just itself.
                targets.Add(new(entityType, node.Id, VaultExportArtifact.P12));
                fields.AddRange([$"{node.Name}.p12", PasswordField]);
            }

            if (options.IncludeCrls && isCa && latestCrls.TryGetValue(node.Id, out var crlId))
            {
                targets.Add(new("Crl", crlId, VaultExportArtifact.Crl));
                fields.Add($"{node.Name}.crl");
            }

            secrets.Add(new VaultBackupSecret(group.Path, node.Name, targets, fields));
        }

        return new VaultBackupPlan(trustDomain.Id, trustDomain.Name, trustDomain.VaultNamespace,
            settings.Address!, settings.Mount, options, secrets, certificateOnly, superseded, excluded);
    }

    private sealed record Node(int Id, string Name, int? ParentId, int? RenewalOfId, string SerialNumber, int TrustDomainId);

    private sealed record Generation(Node Node, bool IsCa, bool HasKey, bool Excluded, DateTime? ExportedAt)
    {
        public string EntityType => IsCa ? "CaCertificate" : "IssuedCertificate";
    }

    /// <summary>One secret of a trust domain: the renewal generations that share its path, oldest first.</summary>
    private sealed record SecretGroup(string Path, IReadOnlyList<Generation> Generations)
    {
        public Generation Newest => Generations[^1];

        /// <summary>Leaving out any generation leaves out the secret they share.</summary>
        public bool Excluded => Generations.Any(g => g.Excluded);

        /// <summary>An earlier generation went to Vault, but the newest hasn't.</summary>
        public bool NeedsUpdate => !Excluded && Newest.ExportedAt == null && Generations.Any(g => g.ExportedAt != null);
    }

    /// <summary>The trust domain's secrets, in path order, and the latest CRL of each of its CAs.</summary>
    private static async Task<(TrustDomain TrustDomain, List<SecretGroup> Groups, Dictionary<int, int> LatestCrls)> LoadSecretsAsync(
        SigyllDbContext db, int trustDomainId, CancellationToken ct)
    {
        var trustDomain = await db.TrustDomains.AsNoTracking().SingleOrDefaultAsync(t => t.Id == trustDomainId, ct)
            ?? throw new ArgumentException("Trust domain not found.");

        var hierarchy = await Hierarchy.LoadAsync(db, ct);
        var cas = await db.CaCertificates.AsNoTracking()
            .Where(c => c.TrustDomainId == trustDomainId)
            .Select(c => new { c.Id, HasKey = c.EncryptedPfxBytes != null, c.VaultBackupExcluded, c.VaultExportedAt })
            .ToDictionaryAsync(c => c.Id, ct);
        var caIds = cas.Keys.ToList();
        var issued = await db.IssuedCertificates.AsNoTracking()
            .Where(c => caIds.Contains(c.IssuingCaCertificateId))
            .Select(c => new { c.Id, HasKey = c.EncryptedPfxBytes != null, c.VaultBackupExcluded, c.VaultExportedAt })
            .ToDictionaryAsync(c => c.Id, ct);
        var latestCrls = (await db.Crls.AsNoTracking()
                .Where(c => caIds.Contains(c.CaCertificateId))
                .Select(c => new { c.Id, c.CaCertificateId, c.CrlNumber })
                .ToListAsync(ct))
            .GroupBy(c => c.CaCertificateId)
            .ToDictionary(g => g.Key, g => g.MaxBy(c => c.CrlNumber)!.Id);

        // Every certificate with its secret's path; CAs root first, then what each CA issued.
        var entries = new List<(string Path, Generation Generation)>();
        foreach (var ca in hierarchy.Cas.Values.Where(c => cas.ContainsKey(c.Id)).OrderBy(c => c.Id))
        {
            var row = cas[ca.Id];
            entries.Add((await hierarchy.RelativePathAsync(trustDomain.Name, ca, null, ct),
                new Generation(ca, true, row.HasKey, row.VaultBackupExcluded, row.VaultExportedAt)));
            foreach (var node in await hierarchy.IssuedUnderAsync(ca.Id, ct))
            {
                var cert = issued[node.Id];
                entries.Add((await hierarchy.RelativePathAsync(trustDomain.Name, ca, node, ct),
                    new Generation(node, false, cert.HasKey, cert.VaultBackupExcluded, cert.VaultExportedAt)));
            }
        }

        var groups = entries.GroupBy(e => e.Path)
            .OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new SecretGroup(g.Key, g.Select(e => e.Generation).OrderBy(x => x.Node.Id).ToList()))
            .ToList();
        return (trustDomain, groups, latestCrls);
    }

    /// <summary>All CAs, and the certificates each issued as they're asked for, to work out secret paths.</summary>
    private sealed class Hierarchy
    {
        private readonly SigyllDbContext _db;
        private readonly Dictionary<int, List<Node>> _issuedByCa = new();

        private Hierarchy(SigyllDbContext db, Dictionary<int, Node> cas)
        {
            _db = db;
            Cas = cas;
        }

        public Dictionary<int, Node> Cas { get; }

        public static async Task<Hierarchy> LoadAsync(SigyllDbContext db, CancellationToken ct) =>
            new(db, await db.CaCertificates.AsNoTracking()
                .Select(c => new Node(c.Id, c.Name, c.ParentId, c.RenewalOfId, c.SerialNumber, c.TrustDomainId))
                .ToDictionaryAsync(c => c.Id, ct));

        public async Task<List<Node>> IssuedUnderAsync(int caId, CancellationToken ct)
        {
            if (!_issuedByCa.TryGetValue(caId, out var issued))
                _issuedByCa[caId] = issued = await _db.IssuedCertificates.AsNoTracking()
                    .Where(c => c.IssuingCaCertificateId == caId)
                    .Select(c => new Node(c.Id, c.Name, c.IssuingCaCertificateId, c.RenewalOfId, c.SerialNumber, 0))
                    .ToListAsync(ct);
            return issued;
        }

        /// <summary>The secret's path below the namespace for <paramref name="ca"/>, or for <paramref name="issued"/> under it.</summary>
        public async Task<string> RelativePathAsync(string trustDomainName, Node ca, Node? issued, CancellationToken ct)
        {
            // Root first.
            var chain = new List<Node>();
            var visited = new HashSet<int>();
            for (Node? n = ca; n != null && visited.Add(n.Id); n = n.ParentId is int p ? Cas.GetValueOrDefault(p) : null)
                chain.Insert(0, n);

            var segments = new List<string> { Slug(trustDomainName) };
            foreach (var node in chain)
            {
                var issuedSiblings = node.ParentId is int parent ? await IssuedUnderAsync(parent, ct) : [];
                var caSiblings = Cas.Values.Where(c => c.ParentId == node.ParentId && (node.ParentId != null || c.TrustDomainId == node.TrustDomainId));
                segments.Add(Segment(node, isCa: true, caSiblings, issuedSiblings, Cas));
            }

            if (issued != null)
            {
                var caSiblings = Cas.Values.Where(c => c.ParentId == issued.ParentId);
                segments.Add(Segment(issued, isCa: false, caSiblings, await IssuedUnderAsync(issued.ParentId!.Value, ct), Cas));
            }

            return string.Join('/', segments);
        }
    }

    /// <summary>
    /// The path segment for one certificate: the name of its first generation made path-safe, so a renewal keeps
    /// its predecessor's segment even when renamed and consumers read the newest generation at the same path. When
    /// an unrelated sibling lineage has the same name, every lineage but the oldest adds the end of its first serial
    /// number.
    /// </summary>
    private static string Segment(Node node, bool isCa, IEnumerable<Node> caSiblings, List<Node> issuedSiblings, Dictionary<int, Node> cas)
    {
        var issuedById = issuedSiblings.ToDictionary(n => n.Id);
        Node Lineage(Node n, bool ca)
        {
            var seen = new HashSet<int>();
            while (n.RenewalOfId is int prev && seen.Add(n.Id)
                   && (ca ? cas.GetValueOrDefault(prev) : issuedById.GetValueOrDefault(prev)) is { } p)
                n = p;
            return n;
        }

        var mine = Lineage(node, isCa);
        var slug = Slug(mine.Name);

        // The lineages (CAs before issued certificates, oldest first) whose first generation has this name.
        var lineages = caSiblings.Select(c => (Ca: true, Root: Lineage(c, true)))
            .Concat(issuedSiblings.Select(c => (Ca: false, Root: Lineage(c, false))))
            .Where(s => Slug(s.Root.Name) == slug)
            .Select(s => (s.Ca, Root: s.Root.Id))
            .Distinct()
            .OrderBy(s => s.Ca ? 0 : 1).ThenBy(s => s.Root)
            .ToList();
        if (lineages.Count <= 1 || lineages[0] == (isCa, mine.Id))
            return slug;

        var serial = mine.SerialNumber.ToLowerInvariant();
        return $"{slug}-{(serial.Length > 8 ? serial[^8..] : serial)}";
    }

    /// <summary>A name made safe for a Vault path segment: lowercase letters, digits, '.', '_' and '-'.</summary>
    public static string Slug(string name)
    {
        var slug = NotPathSafe().Replace(name.Trim().ToLowerInvariant(), "-").Trim('-', '.');
        return slug.Length == 0 ? "unnamed" : slug;
    }

    /// <summary>A namespace or mount as "a/b", or null when it's empty or not path-safe.</summary>
    public static string? NormalizeFolder(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var segments = value.Trim().Trim('/').Split('/');
        return segments.All(s => FolderSegment().IsMatch(s) && s is not "." and not "..")
            ? string.Join('/', segments)
            : null;
    }

    [GeneratedRegex("[^a-z0-9._-]+")]
    private static partial Regex NotPathSafe();

    [GeneratedRegex("^[A-Za-z0-9._-]+$")]
    private static partial Regex FolderSegment();
}
