#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Data.Entities;

/// <summary>
/// One entry in the append-only audit trail: who did what to which record, and whether it worked. The database
/// refuses updates and deletes and stamps <see cref="OccurredAt"/> itself; see V8__audit_trail.sql.
/// </summary>
public class AuditEvent
{
    public long Id { get; set; }

    /// <summary>When the event was recorded (UTC). Set by the database on insert.</summary>
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>Operator account or system actor (a recurring job, the RA client).</summary>
    public string Actor { get; set; } = string.Empty;

    public bool ActorIsSystem { get; set; }

    /// <summary>One of <see cref="Services.Audit.AuditActions"/>.</summary>
    public string Action { get; set; } = string.Empty;

    public bool Succeeded { get; set; } = true;

    /// <summary>CaCertificate, IssuedCertificate, Crl, ExternalCertificateRequest, TrustDomain or Operator.</summary>
    public string? EntityType { get; set; }

    /// <summary>The record's id. No foreign key: the record may since have been deleted.</summary>
    public int? EntityId { get; set; }

    public string? EntityName { get; set; }

    public string? Subject { get; set; }

    public string? Thumbprint { get; set; }

    public int? TrustDomainId { get; set; }

    /// <summary>Further facts in plain text: revocation reason, export format, roles granted.</summary>
    public string? Detail { get; set; }
}
