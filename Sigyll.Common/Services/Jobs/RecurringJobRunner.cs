#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Diagnostics;
using Cronos;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;

namespace Sigyll.Common.Services.Jobs;

/// <summary>
/// Runs recurring jobs from the <c>RecurringJobs</c> table: creates a row for each registered
/// <see cref="IRecurringJobDefinition"/>, runs the due ones, and records the outcome and next run.
/// On PostgreSQL a session advisory lock makes sure only one Sigyll instance runs jobs at a time.
/// </summary>
public class RecurringJobRunner
{
    /// <summary>Advisory lock key shared by every Sigyll instance on the same database.</summary>
    private const long AdvisoryLockKey = 7_316_455_001;

    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RecurringJobRunner> _logger;

    public RecurringJobRunner(
        IDbContextFactory<SigyllDbContext> dbFactory,
        IServiceScopeFactory scopeFactory,
        ILogger<RecurringJobRunner> logger)
    {
        _dbFactory = dbFactory;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <summary>Parses a five-field cron expression; throws <see cref="FormatException"/> when invalid.</summary>
    public static CronExpression ParseCron(string cron)
    {
        try
        {
            return CronExpression.Parse(cron.Trim());
        }
        catch (CronFormatException ex)
        {
            throw new FormatException($"'{cron}' is not a valid cron expression: {ex.Message}", ex);
        }
    }

    public static DateTime? NextOccurrence(string cron, DateTime fromUtc) =>
        ParseCron(cron).GetNextOccurrence(DateTime.SpecifyKind(fromUtc, DateTimeKind.Utc));

    /// <summary>Adds a schedule row for every registered job that has none yet.</summary>
    public async Task EnsureRegisteredAsync(CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var definitions = scope.ServiceProvider.GetServices<IRecurringJobDefinition>().ToList();

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var existing = await db.RecurringJobs.Select(j => j.Id).ToListAsync(ct);
        foreach (var definition in definitions.Where(d => !existing.Contains(d.JobId)))
        {
            db.RecurringJobs.Add(new RecurringJob
            {
                Id = definition.JobId,
                Cron = definition.DefaultCron,
                NextRunAt = NextOccurrence(definition.DefaultCron, DateTime.UtcNow),
            });
            _logger.LogInformation("Registered recurring job {JobId} ({Cron})", definition.JobId, definition.DefaultCron);
        }

        // Rows carried over without a next run (e.g. a migrated schedule) get one now.
        foreach (var row in await db.RecurringJobs.Where(j => j.Enabled && j.NextRunAt == null).ToListAsync(ct))
        {
            row.NextRunAt = NextOccurrence(row.Cron, DateTime.UtcNow);
            row.UpdatedAt = DateTime.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Runs every enabled job whose next run is due. Returns how many ran.</summary>
    public async Task<int> RunDueJobsAsync(CancellationToken ct = default)
    {
        await using var lockDb = await _dbFactory.CreateDbContextAsync(ct);
        var usesLock = lockDb.Database.IsNpgsql();
        if (usesLock)
        {
            await lockDb.Database.OpenConnectionAsync(ct);
            var acquired = await lockDb.Database
                .SqlQuery<bool>($"SELECT pg_try_advisory_lock({AdvisoryLockKey}) AS \"Value\"")
                .SingleAsync(ct);
            if (!acquired)
                return 0; // another instance is running jobs
        }

        try
        {
            var now = DateTime.UtcNow;
            List<string> dueIds;
            await using (var db = await _dbFactory.CreateDbContextAsync(ct))
            {
                dueIds = await db.RecurringJobs
                    .Where(j => j.Enabled && j.NextRunAt != null && j.NextRunAt <= now)
                    .OrderBy(j => j.NextRunAt)
                    .Select(j => j.Id)
                    .ToListAsync(ct);
            }

            foreach (var id in dueIds)
                await RunAsync(id, ct);
            return dueIds.Count;
        }
        finally
        {
            if (usesLock)
            {
                await lockDb.Database.ExecuteSqlAsync($"SELECT pg_advisory_unlock({AdvisoryLockKey})", CancellationToken.None);
                await lockDb.Database.CloseConnectionAsync();
            }
        }
    }

    private async Task RunAsync(string jobId, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var definition = scope.ServiceProvider.GetServices<IRecurringJobDefinition>().FirstOrDefault(d => d.JobId == jobId);

        var stopwatch = Stopwatch.StartNew();
        string result;
        string? error = null;
        if (definition == null)
        {
            result = "Failed";
            error = $"Job '{jobId}' is scheduled but not registered in this build.";
            _logger.LogWarning("Recurring job {JobId} is scheduled but not registered", jobId);
        }
        else
        {
            try
            {
                await definition.ExecuteAsync(ct);
                result = "Succeeded";
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                result = "Failed";
                error = ex.Message;
                _logger.LogError(ex, "Recurring job {JobId} failed", jobId);
            }
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.RecurringJobs.FindAsync([jobId], ct);
        if (row == null) return;
        var finished = DateTime.UtcNow;
        row.LastRunAt = finished;
        row.LastResult = result;
        row.LastError = error;
        row.LastDurationMs = (int)stopwatch.ElapsedMilliseconds;
        row.NextRunAt = NextOccurrence(row.Cron, finished);
        row.UpdatedAt = finished;
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>Database-backed <see cref="IRecurringJobScheduler"/> for the Jobs page.</summary>
public class RecurringJobScheduler : IRecurringJobScheduler
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly RecurringJobSignal _signal;

    public RecurringJobScheduler(IDbContextFactory<SigyllDbContext> dbFactory, RecurringJobSignal signal)
    {
        _dbFactory = dbFactory;
        _signal = signal;
    }

    public async Task<List<RecurringJobInfo>> GetRecurringJobsAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.RecurringJobs
            .OrderBy(j => j.Id)
            .Select(j => new RecurringJobInfo(j.Id, j.Cron, j.Enabled, j.LastRunAt, j.NextRunAt,
                j.LastResult, j.LastError, j.LastDurationMs))
            .ToListAsync(ct);
    }

    public async Task UpdateCronExpressionAsync(string jobId, string cronExpression, CancellationToken ct = default)
    {
        var cron = cronExpression.Trim();
        var next = RecurringJobRunner.NextOccurrence(cron, DateTime.UtcNow); // validates
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.RecurringJobs.FindAsync([jobId], ct)
                  ?? throw new InvalidOperationException($"Recurring job '{jobId}' not found.");
        row.Cron = cron;
        row.NextRunAt = next;
        row.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    public async Task TriggerJobAsync(string jobId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.RecurringJobs.FindAsync([jobId], ct)
                  ?? throw new InvalidOperationException($"Recurring job '{jobId}' not found.");
        row.NextRunAt = DateTime.UtcNow;
        row.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        _signal.Wake();
    }
}

/// <summary>Wakes the job loop early, e.g. after "Run Now".</summary>
public class RecurringJobSignal
{
    private readonly SemaphoreSlim _semaphore = new(0, 1);

    public void Wake()
    {
        if (_semaphore.CurrentCount == 0)
        {
            try { _semaphore.Release(); } catch (SemaphoreFullException) { }
        }
    }

    /// <summary>Waits until <see cref="Wake"/> is called or the interval passes.</summary>
    public Task WaitAsync(TimeSpan interval, CancellationToken ct) => _semaphore.WaitAsync(interval, ct);
}
