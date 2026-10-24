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

public record TrustDomainVaultNamespace(int TrustDomainId, string TrustDomainName, string? Namespace);

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

    public async Task<List<TrustDomainVaultNamespace>> GetTrustDomainNamespacesAsync(CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.TrustDomains
            .OrderBy(t => t.Name)
            .Select(t => new TrustDomainVaultNamespace(t.Id, t.Name, t.VaultNamespace))
            .ToListAsync(ct);
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

        var ns = plan.Namespace;
        var settingNamespace = false;
        if (ns == null)
        {
            ns = NormalizeFolder(firstNamespace)
                ?? throw new ArgumentException($"Choose the Vault namespace for trust domain {plan.TrustDomainName}. {InvalidNamespaceMessage}");
            settingNamespace = true;
        }
        else if (!string.IsNullOrWhiteSpace(firstNamespace) && NormalizeFolder(firstNamespace) != ns)
        {
            throw new InvalidOperationException(
                $"Trust domain {plan.TrustDomainName} already exports to namespace {ns}; only an Admin can change it.");
        }

        var fields = await BuildFieldsAsync(db, target, ct);
        var path = plan.PathFor(ns);
        var version = await _vault.MergeAsync(new Uri(settings.Address!), token.Trim(), settings.Mount, path, fields, ct);

        if (settingNamespace)
        {
            var trustDomain = await db.TrustDomains.FindAsync([plan.TrustDomainId], ct);
            if (trustDomain is { VaultNamespace: null })
            {
                trustDomain.VaultNamespace = ns;
                await db.SaveChangesAsync(ct);
                _logger.LogInformation("{Actor} set the Vault namespace of trust domain {TrustDomain} to {Namespace}",
                    identity.Name, plan.TrustDomainName, ns);
            }
        }

        _logger.LogInformation(
            "{Actor} exported {Fields} of {EntityType} {Id} to Vault {Address} {Mount}/{Path} (version {Version})",
            identity.Name, string.Join(", ", fields.Keys), target.EntityType, target.Id, settings.Address, settings.Mount, path, version);

        return new VaultExportResult(settings.Address!, settings.Mount, path, version, fields.Keys.ToList());
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

        var cas = await db.CaCertificates.AsNoTracking()
            .Select(c => new Node(c.Id, c.Name, c.ParentId, c.RenewalOfId, c.SerialNumber, c.TrustDomainId))
            .ToDictionaryAsync(c => c.Id, ct);
        if (!cas.TryGetValue(caId, out var ca))
            throw new ArgumentException("Certificate not found.");

        // Root first.
        var chain = new List<Node>();
        var visited = new HashSet<int>();
        for (Node? n = ca; n != null && visited.Add(n.Id); n = n.ParentId is int p ? cas.GetValueOrDefault(p) : null)
            chain.Insert(0, n);

        var segments = new List<string>();
        foreach (var node in chain)
        {
            var issuedSiblings = node.ParentId is int parent ? await IssuedUnderAsync(db, parent, ct) : [];
            var caSiblings = cas.Values.Where(c => c.ParentId == node.ParentId && (node.ParentId != null || c.TrustDomainId == node.TrustDomainId));
            segments.Add(Segment(node, isCa: true, caSiblings, issuedSiblings, cas));
        }

        if (issued != null)
        {
            var node = new Node(issued.Id, issued.Name, issued.IssuingCaCertificateId, issued.RenewalOfId, issued.SerialNumber, ca.TrustDomainId);
            var issuedSiblings = await IssuedUnderAsync(db, issued.IssuingCaCertificateId, ct);
            var caSiblings = cas.Values.Where(c => c.ParentId == issued.IssuingCaCertificateId);
            segments.Add(Segment(node, isCa: false, caSiblings, issuedSiblings, cas));
        }

        var trustDomain = await db.TrustDomains.AsNoTracking().SingleAsync(t => t.Id == ca.TrustDomainId, ct);
        var relativePath = string.Join('/', segments.Prepend(Slug(trustDomain.Name)));

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

    /// <summary>The field holding the password of the secret's .p12 files (the certificate's stored key password).</summary>
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

    private sealed record Node(int Id, string Name, int? ParentId, int? RenewalOfId, string SerialNumber, int TrustDomainId);

    private static async Task<List<Node>> IssuedUnderAsync(SigyllDbContext db, int caId, CancellationToken ct) =>
        await db.IssuedCertificates.AsNoTracking()
            .Where(c => c.IssuingCaCertificateId == caId)
            .Select(c => new Node(c.Id, c.Name, c.IssuingCaCertificateId, c.RenewalOfId, c.SerialNumber, 0))
            .ToListAsync(ct);

    /// <summary>
    /// The path segment for one certificate: its name made path-safe. A renewal keeps its predecessor's segment,
    /// so consumers read the newest generation at the same path. When an unrelated sibling has the same name,
    /// every lineage but the oldest adds the end of its first serial number.
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

        var slug = Slug(node.Name);
        var mine = Lineage(node, isCa);

        // The lineages (CAs before issued certificates, oldest first) with a certificate of this name.
        var lineages = caSiblings.Select(c => (Ca: true, Name: c.Name, Root: Lineage(c, true).Id))
            .Concat(issuedSiblings.Select(c => (Ca: false, Name: c.Name, Root: Lineage(c, false).Id)))
            .Where(s => Slug(s.Name) == slug)
            .Select(s => (s.Ca, s.Root))
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
