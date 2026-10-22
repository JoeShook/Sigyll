#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Sigyll.Common.Services.Jobs;
using Sigyll.UI.Security;

namespace Sigyll.UI.Components.Pages;

public partial class Jobs : IDisposable
{
    [Inject] private IRecurringJobScheduler JobScheduler { get; set; } = null!;
    [Inject] private CrlGenerationService CrlGenerationService { get; set; } = null!;
    [Inject] private Services.TimeDisplayService TimeDisplay { get; set; } = null!;
    [Inject] private OperatorAccess Access { get; set; } = null!;

    private bool isLoading = true;
    private List<CrlStatusRow> crlStatuses = new();
    private Dictionary<string, List<CrlStatusRow>> crlStatusesByTrustDomain = new();
    private List<RecurringJobRow> recurringJobs = new();

    protected override async Task OnInitializedAsync()
    {
        TimeDisplay.OnChanged += StateHasChanged;
        await Access.LoadAsync();
        await LoadRecurringJobsAsync();
        await LoadCrlStatusesAsync();
        isLoading = false;
    }

    private async Task LoadRecurringJobsAsync()
    {
        var jobs = await JobScheduler.GetRecurringJobsAsync();
        recurringJobs = jobs.Select(j => new RecurringJobRow
        {
            JobId = j.JobId,
            OriginalCron = j.CronExpression,
            EditableCron = j.CronExpression,
            LastRunAt = j.LastRunAt,
            NextRunAt = j.NextRunAt,
            LastResult = j.LastResult,
            LastError = j.LastError,
            LastDurationMs = j.LastDurationMs,
        }).ToList();
    }

    private async Task SaveCron(RecurringJobRow row)
    {
        try
        {
            await JobScheduler.UpdateCronExpressionAsync(row.JobId, row.EditableCron);
            row.CronError = null;
            await LoadRecurringJobsAsync();
        }
        catch (FormatException ex)
        {
            row.CronError = ex.Message;
        }
    }

    private async Task TriggerJob(RecurringJobRow row)
    {
        await JobScheduler.TriggerJobAsync(row.JobId);
        row.Triggered = true;

        // The runner picks it up within a second or two; refresh to show the outcome.
        await Task.Delay(TimeSpan.FromSeconds(3));
        await LoadRecurringJobsAsync();
        await LoadCrlStatusesAsync();
    }

    private string When(DateTime? utc) => utc is { } t ? TimeDisplay.FormatMedium(t) : "—";

    private async Task GenerateCrl(CrlStatusRow row)
    {
        row.IsGenerating = true;
        StateHasChanged();

        var result = await CrlGenerationService.GenerateCrlAsync(row.CaId);

        row.IsGenerating = false;

        // Refresh the data to show the new CRL
        await LoadCrlStatusesAsync();
        StateHasChanged();
    }

    private async Task LoadCrlStatusesAsync()
    {
        var summaries = await CrlGenerationService.GetCrlStatusesAsync();

        crlStatuses = summaries.Select(s => new CrlStatusRow
        {
            CaId = s.CaId,
            CaName = s.CaName,
            TrustDomainName = s.TrustDomainName,
            LatestCrlNumber = s.LatestCrlNumber,
            NextUpdate = s.NextUpdate,
            HasCrl = s.HasCrl,
            NeedsRenewal = s.NeedsRenewal,
            RevokedCount = s.RevokedCount
        }).ToList();

        crlStatusesByTrustDomain = crlStatuses
            .GroupBy(s => s.TrustDomainName)
            .OrderBy(g => g.Key)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    private class RecurringJobRow
    {
        public string JobId { get; init; } = string.Empty;
        public string OriginalCron { get; set; } = string.Empty;
        public string EditableCron { get; set; } = string.Empty;
        public string? CronError { get; set; }
        public bool Triggered { get; set; }
        public DateTime? LastRunAt { get; init; }
        public DateTime? NextRunAt { get; init; }
        public string? LastResult { get; init; }
        public string? LastError { get; init; }
        public int? LastDurationMs { get; init; }
    }

    private class CrlStatusRow
    {
        public int CaId { get; init; }
        public string CaName { get; init; } = string.Empty;
        public string TrustDomainName { get; init; } = string.Empty;
        public long? LatestCrlNumber { get; init; }
        public DateTime NextUpdate { get; init; }
        public bool HasCrl { get; init; }
        public bool NeedsRenewal { get; init; }
        public int RevokedCount { get; init; }
        public bool IsGenerating { get; set; }
    }

    public void Dispose()
    {
        TimeDisplay.OnChanged -= StateHasChanged;
    }
}
