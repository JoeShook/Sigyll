#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Services.Jobs;

public record RecurringJobInfo(
    string JobId,
    string CronExpression,
    bool Enabled,
    DateTime? LastRunAt,
    DateTime? NextRunAt,
    string? LastResult,
    string? LastError,
    int? LastDurationMs);

/// <summary>
/// Read and change recurring job schedules from the UI.
/// </summary>
public interface IRecurringJobScheduler
{
    Task<List<RecurringJobInfo>> GetRecurringJobsAsync(CancellationToken ct = default);

    /// <summary>Changes a job's schedule. Throws <see cref="FormatException"/> for an invalid cron expression.</summary>
    Task UpdateCronExpressionAsync(string jobId, string cronExpression, CancellationToken ct = default);

    /// <summary>Makes the job due now; the runner picks it up within seconds.</summary>
    Task TriggerJobAsync(string jobId, CancellationToken ct = default);
}

/// <summary>
/// A recurring background job. Register implementations in DI; <see cref="RecurringJobRunner"/>
/// creates the schedule row on first start and runs the job when it is due.
/// </summary>
public interface IRecurringJobDefinition
{
    /// <summary>Stable key, stored as the schedule row's id.</summary>
    string JobId { get; }

    /// <summary>Schedule used when the job's row is first created.</summary>
    string DefaultCron { get; }

    Task ExecuteAsync(CancellationToken ct);
}
