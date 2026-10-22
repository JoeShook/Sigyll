#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Services.Jobs;

namespace Sigyll.Services;

/// <summary>
/// Runs due recurring jobs every 30 seconds, or straight away when "Run Now" wakes it.
/// </summary>
public class RecurringJobHostedService : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);

    private readonly RecurringJobRunner _runner;
    private readonly RecurringJobSignal _signal;
    private readonly ILogger<RecurringJobHostedService> _logger;

    public RecurringJobHostedService(
        RecurringJobRunner runner,
        RecurringJobSignal signal,
        ILogger<RecurringJobHostedService> logger)
    {
        _runner = runner;
        _signal = signal;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _runner.EnsureRegisteredAsync(stoppingToken);
        }
        catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Could not register recurring jobs");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _runner.RunDueJobsAsync(stoppingToken);
                await _signal.WaitAsync(PollInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A database outage must not kill the loop; try again on the next tick.
                _logger.LogError(ex, "Recurring job loop failed");
                await Task.Delay(PollInterval, stoppingToken).ContinueWith(_ => { }, CancellationToken.None);
            }
        }
    }
}
