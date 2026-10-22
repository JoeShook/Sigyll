#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.Services.Jobs;

namespace Sigyll.Signing.Tests;

public class RecurringJobRunnerTests
{
    private readonly TestDbContextFactory _dbFactory = new();
    private readonly FakeJob _ok = new("ok-job");
    private readonly FakeJob _broken = new("broken-job", fail: true);
    private readonly RecurringJobRunner _runner;
    private readonly RecurringJobScheduler _scheduler;

    public RecurringJobRunnerTests()
    {
        var services = new ServiceCollection();
        services.AddScoped<OperatorContext>();
        services.AddScoped<IOperatorContext>(sp => sp.GetRequiredService<OperatorContext>());
        services.AddScoped<IRecurringJobDefinition>(sp => _ok.InScope(sp));
        services.AddScoped<IRecurringJobDefinition>(sp => _broken.InScope(sp));
        var provider = services.BuildServiceProvider();
        _runner = new RecurringJobRunner(_dbFactory, provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<RecurringJobRunner>.Instance);
        _scheduler = new RecurringJobScheduler(_dbFactory, TestOperators.Full, new RecurringJobSignal());
    }

    [Fact]
    public async Task EnsureRegistered_CreatesOneRowPerJob_WithItsDefaultScheduleAndNextRun()
    {
        await _runner.EnsureRegisteredAsync();
        await _runner.EnsureRegisteredAsync(); // idempotent

        var jobs = await _scheduler.GetRecurringJobsAsync();
        jobs.Select(j => j.JobId).ShouldBe(["broken-job", "ok-job"]);
        jobs.ShouldAllBe(j => j.CronExpression == "0 * * * *" && j.Enabled && j.NextRunAt > DateTime.UtcNow);
        jobs.ShouldAllBe(j => j.LastRunAt == null && j.LastResult == null);
    }

    [Fact]
    public async Task NothingRuns_UntilAJobIsDue()
    {
        await _runner.EnsureRegisteredAsync();

        (await _runner.RunDueJobsAsync()).ShouldBe(0);
        _ok.Runs.ShouldBe(0);
    }

    [Fact]
    public async Task RunNow_RunsTheJob_AndRecordsSuccessAndTheNextRun()
    {
        await _runner.EnsureRegisteredAsync();
        await _scheduler.TriggerJobAsync("ok-job");

        (await _runner.RunDueJobsAsync()).ShouldBe(1);

        _ok.Runs.ShouldBe(1);
        _ok.RanAs.ShouldBe(RecurringJobRunner.Scheduler);
        _broken.Runs.ShouldBe(0);
        var job = (await _scheduler.GetRecurringJobsAsync()).Single(j => j.JobId == "ok-job");
        job.LastResult.ShouldBe("Succeeded");
        job.LastError.ShouldBeNull();
        job.LastRunAt.ShouldNotBeNull();
        job.LastDurationMs.ShouldNotBeNull();
        job.NextRunAt.ShouldNotBeNull();
        job.NextRunAt!.Value.ShouldBeGreaterThan(job.LastRunAt!.Value);
        job.NextRunAt.Value.Minute.ShouldBe(0); // hourly, on the hour
    }

    [Fact]
    public async Task AFailingJob_RecordsTheError_AndIsScheduledAgain()
    {
        await _runner.EnsureRegisteredAsync();
        await _scheduler.TriggerJobAsync("broken-job");

        await _runner.RunDueJobsAsync();

        var job = (await _scheduler.GetRecurringJobsAsync()).Single(j => j.JobId == "broken-job");
        job.LastResult.ShouldBe("Failed");
        job.LastError.ShouldBe("boom");
        job.NextRunAt.ShouldNotBeNull();
        job.NextRunAt!.Value.ShouldBeGreaterThan(DateTime.UtcNow);
    }

    [Fact]
    public async Task AScheduledJobWithNoCode_IsMarkedFailed()
    {
        await using (var db = _dbFactory.CreateDbContext())
        {
            db.RecurringJobs.Add(new RecurringJob { Id = "retired-job", Cron = "0 0 * * *", NextRunAt = DateTime.UtcNow.AddMinutes(-1) });
            await db.SaveChangesAsync();
        }

        await _runner.RunDueJobsAsync();

        var job = (await _scheduler.GetRecurringJobsAsync()).Single(j => j.JobId == "retired-job");
        job.LastResult.ShouldBe("Failed");
        job.LastError!.ShouldContain("not registered");
    }

    [Fact]
    public async Task UpdateCron_ValidatesAndReschedules()
    {
        await _runner.EnsureRegisteredAsync();

        await Should.ThrowAsync<FormatException>(() => _scheduler.UpdateCronExpressionAsync("ok-job", "every hour"));

        await _scheduler.UpdateCronExpressionAsync("ok-job", " */5 * * * * ");
        var job = (await _scheduler.GetRecurringJobsAsync()).Single(j => j.JobId == "ok-job");
        job.CronExpression.ShouldBe("*/5 * * * *");
        (job.NextRunAt!.Value - DateTime.UtcNow).ShouldBeLessThanOrEqualTo(TimeSpan.FromMinutes(5));
    }

    private sealed class FakeJob(string id, bool fail = false) : IRecurringJobDefinition
    {
        private IOperatorContext? _operator;

        public int Runs { get; private set; }
        public OperatorIdentity? RanAs { get; private set; }
        public string JobId => id;
        public string DefaultCron => "0 * * * *";

        public FakeJob InScope(IServiceProvider scope)
        {
            _operator = scope.GetRequiredService<IOperatorContext>();
            return this;
        }

        public async Task ExecuteAsync(CancellationToken ct)
        {
            Runs++;
            RanAs = await _operator!.GetCurrentAsync();
            if (fail) throw new InvalidOperationException("boom");
        }
    }
}
