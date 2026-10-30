#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;

namespace Sigyll.Common.Services.Audit;

/// <summary>The actions the audit trail records. Stored as text: never rename one, add a new code instead.</summary>
public static class AuditActions
{
    public const string CertificateIssued = "certificate.issued";
    public const string CertificateImported = "certificate.imported";
    public const string CertificateRevoked = "certificate.revoked";
    public const string CertificateDeleted = "certificate.deleted";
    public const string CertificateArchived = "certificate.archived";
    public const string CertificateMoved = "certificate.moved";
    public const string CrlGenerated = "crl.generated";
    public const string CrlImported = "crl.imported";
    public const string CrlDeleted = "crl.deleted";
    public const string KeyExported = "key.exported";
    public const string VaultExported = "vault.exported";
    public const string VaultBackedUp = "vault.backed-up";
    public const string VaultUpdated = "vault.updated";
    public const string VaultSecretsRemoved = "vault.secrets-removed";
    public const string RequestCreated = "request.created";
    public const string RequestFulfilled = "request.fulfilled";
    public const string RequestDeleted = "request.deleted";
    public const string TrustDomainDeleted = "trust-domain.deleted";
    public const string OperatorCreated = "operator.created";
    public const string OperatorDeleted = "operator.deleted";
    public const string OperatorRolesChanged = "operator.roles-changed";
    public const string OperatorPasswordSet = "operator.password-set";
    public const string OperatorUnlocked = "operator.unlocked";
    public const string OperatorSecondFactorReset = "operator.second-factor-reset";
    public const string OperatorSignedIn = "operator.signed-in";
    public const string OperatorSignInFailed = "operator.sign-in-failed";
    public const string OperatorLockedOut = "operator.locked-out";
    public const string OperatorSignedOut = "operator.signed-out";

    public static readonly string[] All =
    [
        CertificateIssued, CertificateImported, CertificateRevoked, CertificateDeleted, CertificateArchived,
        CertificateMoved, CrlGenerated, CrlImported, CrlDeleted, KeyExported, VaultExported, VaultBackedUp, VaultUpdated,
        VaultSecretsRemoved, RequestCreated, RequestFulfilled, RequestDeleted, TrustDomainDeleted, OperatorCreated,
        OperatorDeleted, OperatorRolesChanged, OperatorPasswordSet, OperatorUnlocked, OperatorSecondFactorReset,
        OperatorSignedIn, OperatorSignInFailed, OperatorLockedOut, OperatorSignedOut,
    ];
}

/// <summary>The record an audit event is about, as it was at the time.</summary>
public sealed record AuditTarget(
    string EntityType, int? EntityId, string? Name = null, string? Subject = null, string? Thumbprint = null,
    int? TrustDomainId = null)
{
    public static AuditTarget Of(CaCertificate ca) =>
        new("CaCertificate", ca.Id, ca.Name, ca.Subject, ca.Thumbprint, ca.TrustDomainId);

    public static AuditTarget Of(IssuedCertificate issued, int? trustDomainId = null) =>
        new("IssuedCertificate", issued.Id, issued.Name, issued.Subject, issued.Thumbprint,
            trustDomainId ?? issued.IssuingCaCertificate?.TrustDomainId);

    public static AuditTarget Of(ExternalCertificateRequest request) =>
        new("ExternalCertificateRequest", request.Id, request.Name, request.SubjectDn, null, request.TrustDomainId);

    public static AuditTarget Of(TrustDomain trustDomain) =>
        new("TrustDomain", trustDomain.Id, trustDomain.Name, TrustDomainId: trustDomain.Id);

    public static AuditTarget Of(Crl crl, int? trustDomainId = null) =>
        new("Crl", crl.Id, $"CRL #{crl.CrlNumber}", TrustDomainId: trustDomainId ?? crl.CaCertificate?.TrustDomainId);

    public static AuditTarget Operator(string account) => new("Operator", null, account);
}

/// <summary>Which audit events to list. Every filter is optional; the newest events come first.</summary>
public sealed record AuditQuery(
    DateTime? From = null, DateTime? To = null, string? Action = null, string? Actor = null, string? Text = null,
    string? EntityType = null, int? EntityId = null, int Skip = 0, int Take = 100);

public sealed record AuditPage(IReadOnlyList<AuditEvent> Events, int Total);

/// <summary>
/// The append-only audit trail. Services record each action they perform once it has happened; an export of a
/// private key is recorded before the key is handed over, so a key never leaves without a record of it.
/// </summary>
public class AuditTrail
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IOperatorContext _operator;

    public AuditTrail(IDbContextFactory<SigyllDbContext> dbFactory, IOperatorContext operatorContext)
    {
        _dbFactory = dbFactory;
        _operator = operatorContext;
    }

    /// <summary>Adds an event. Throws if it can't be stored; a caller releasing a key must not go on.</summary>
    [NoOperatorCheck("Records an action the caller has already authorized, on behalf of the actor it names.")]
    public async Task RecordAsync(OperatorIdentity actor, string action, AuditTarget? target = null,
        string? detail = null, bool succeeded = true, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        db.AuditEvents.Add(new AuditEvent
        {
            Actor = Truncate(actor.Name, 256)!,
            ActorIsSystem = actor.IsSystem,
            Action = action,
            Succeeded = succeeded,
            EntityType = target?.EntityType,
            EntityId = target?.EntityId,
            EntityName = Truncate(target?.Name, 256),
            Subject = Truncate(target?.Subject, 1024),
            Thumbprint = Truncate(target?.Thumbprint, 128),
            TrustDomainId = target?.TrustDomainId,
            Detail = detail,
        });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Adds an event about the certificate, CRL or request with this id, described as it is now.</summary>
    internal async Task RecordAsync(OperatorIdentity actor, string action, string entityType, int entityId,
        string? detail = null, bool succeeded = true, CancellationToken ct = default) =>
        await RecordAsync(actor, action, await TargetAsync(entityType, entityId, ct) ?? new AuditTarget(entityType, entityId),
            detail, succeeded, ct);

    /// <summary>The certificate, CRL or request with this id as an audit target; null if there's none.</summary>
    internal async Task<AuditTarget?> TargetAsync(string entityType, int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return entityType switch
        {
            "CaCertificate" => await db.CaCertificates.AsNoTracking().Where(c => c.Id == id)
                .Select(c => new AuditTarget("CaCertificate", c.Id, c.Name, c.Subject, c.Thumbprint, c.TrustDomainId))
                .FirstOrDefaultAsync(ct),
            "IssuedCertificate" => await db.IssuedCertificates.AsNoTracking().Where(c => c.Id == id)
                .Select(c => new AuditTarget("IssuedCertificate", c.Id, c.Name, c.Subject, c.Thumbprint,
                    c.IssuingCaCertificate.TrustDomainId))
                .FirstOrDefaultAsync(ct),
            "Crl" => await db.Crls.AsNoTracking().Where(c => c.Id == id)
                .Select(c => new AuditTarget("Crl", c.Id, "CRL #" + c.CrlNumber, c.CaCertificate.Subject, null,
                    c.CaCertificate.TrustDomainId))
                .FirstOrDefaultAsync(ct),
            "ExternalCertificateRequest" => await db.ExternalCertificateRequests.AsNoTracking().Where(r => r.Id == id)
                .Select(r => new AuditTarget("ExternalCertificateRequest", r.Id, r.Name, r.SubjectDn, null, r.TrustDomainId))
                .FirstOrDefaultAsync(ct),
            _ => null,
        };
    }

    public async Task<AuditPage> SearchAsync(AuditQuery query, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var events = db.AuditEvents.AsNoTracking();
        if (query.From is { } from)
            events = events.Where(e => e.OccurredAt >= from);
        if (query.To is { } to)
            events = events.Where(e => e.OccurredAt < to);
        if (!string.IsNullOrEmpty(query.Action))
            events = events.Where(e => e.Action == query.Action);
        if (!string.IsNullOrWhiteSpace(query.Actor))
            events = events.Where(e => e.Actor.ToLower().Contains(query.Actor.Trim().ToLower()));
        if (!string.IsNullOrEmpty(query.EntityType))
            events = events.Where(e => e.EntityType == query.EntityType);
        if (query.EntityId is { } entityId)
            events = events.Where(e => e.EntityId == entityId);
        if (!string.IsNullOrWhiteSpace(query.Text))
        {
            var text = query.Text.Trim().ToLower();
            events = events.Where(e =>
                (e.EntityName != null && e.EntityName.ToLower().Contains(text))
                || (e.Subject != null && e.Subject.ToLower().Contains(text))
                || (e.Thumbprint != null && e.Thumbprint.ToLower().Contains(text))
                || (e.Detail != null && e.Detail.ToLower().Contains(text)));
        }

        var total = await events.CountAsync(ct);
        var page = await events.OrderByDescending(e => e.Id)
            .Skip(Math.Max(0, query.Skip))
            .Take(Math.Clamp(query.Take, 1, 500))
            .ToListAsync(ct);
        return new AuditPage(page, total);
    }

    private static string? Truncate(string? value, int length) =>
        value is { Length: > 0 } && value.Length > length ? value[..length] : value;
}
