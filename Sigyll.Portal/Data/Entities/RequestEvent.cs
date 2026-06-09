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
/// Append-only audit entry for a <see cref="CertificateRequest"/> — every state transition and
/// decision is recorded for the RA/compliance trail.
/// </summary>
public class RequestEvent
{
    public int Id { get; set; }

    public int RequestId { get; set; }
    public CertificateRequest Request { get; set; } = null!;

    /// <summary>Who/what caused the event: a user id, "system", or "ra:{userId}".</summary>
    public string Actor { get; set; } = string.Empty;

    /// <summary>Short machine-readable event type, e.g. "Submitted", "PolicyEvaluated", "Approved".</summary>
    public string EventType { get; set; } = string.Empty;

    public string? Detail { get; set; }
    public DateTime At { get; set; } = DateTime.UtcNow;
}
