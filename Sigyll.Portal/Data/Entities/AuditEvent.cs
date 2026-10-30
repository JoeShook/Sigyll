#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Portal.Data.Entities;

/// <summary>
/// One entry in the portal's append-only audit trail of account activity. The database refuses updates and deletes
/// and stamps <see cref="OccurredAt"/> itself; see V3__audit_trail.sql.
/// </summary>
public class AuditEvent
{
    public long Id { get; set; }

    /// <summary>When the event was recorded (UTC). Set by the database on insert.</summary>
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    /// <summary>Account (email) that acted, or "(unknown account)".</summary>
    public string Actor { get; set; } = string.Empty;

    /// <summary>One of <see cref="Services.PortalAuditActions"/>.</summary>
    public string Action { get; set; } = string.Empty;

    public bool Succeeded { get; set; } = true;

    /// <summary>Account the event is about; null when the attempt named no known account.</summary>
    public string? Account { get; set; }

    /// <summary>Further facts in plain text, ending with the client's address when known.</summary>
    public string? Detail { get; set; }
}
