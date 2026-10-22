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
/// Schedule and last outcome of one recurring background job (e.g. CRL auto-renewal).
/// The job code is registered in DI; this row holds what operators can change and observe.
/// </summary>
public class RecurringJob
{
    /// <summary>Stable job key, e.g. "crl-auto-renewal".</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Five-field cron expression, evaluated in UTC.</summary>
    public string Cron { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    /// <summary>When the job is next due (UTC). "Run Now" sets this to the current time.</summary>
    public DateTime? NextRunAt { get; set; }

    public DateTime? LastRunAt { get; set; }

    /// <summary>"Succeeded" or "Failed".</summary>
    public string? LastResult { get; set; }

    public string? LastError { get; set; }

    public int? LastDurationMs { get; set; }

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
