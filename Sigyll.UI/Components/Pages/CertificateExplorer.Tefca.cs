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
using Microsoft.FluentUI.AspNetCore.Components;
using Sigyll.Common.Services.Tefca;
using Sigyll.UI.Services;

namespace Sigyll.UI.Components.Pages;

/// <summary>TEFCA conformance check of the selected end-entity certificate, on demand.</summary>
public partial class CertificateExplorer
{
    [Inject] private TefcaConformanceService TefcaConformance { get; set; } = null!;

    private IReadOnlyList<ConformanceCheckResult>? tefcaResults;
    private bool tefcaResultsOnline;
    private bool isCheckingTefca;

    private bool SelectedIsEndEntity => selectedNode?.EntityType == "IssuedCertificate";

    private async Task RunTefcaCheckAsync(bool online)
    {
        if (selectedNode == null || !SelectedIsEndEntity) return;

        isCheckingTefca = true;
        StateHasChanged();
        try
        {
            tefcaResults = await TefcaConformance.CheckIssuedCertificateAsync(selectedNode.Id, probeReachability: online);
            tefcaResultsOnline = online && TefcaConformance.CanProbeReachability;
            if (tefcaResults == null)
                ToastService.ShowCopyableError("The certificate was not found.");
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"TEFCA check failed: {ex.Message}");
        }
        finally
        {
            isCheckingTefca = false;
            StateHasChanged();
        }
    }

    /// <summary>After issuance from a TEFCA profile: a toast summarizing the automatic check.</summary>
    private void ReportTefcaConformance(IReadOnlyList<ConformanceCheckResult>? results)
    {
        if (results == null) return;

        var failed = results.Where(r => r.Outcome == ConformanceOutcome.Fail).Select(r => r.Name).ToList();
        var warned = results.Count(r => r.Outcome == ConformanceOutcome.Warning);
        if (failed.Count > 0)
            ToastService.ShowWarning($"TEFCA check: {failed.Count} failed ({string.Join("; ", failed)}). Select the certificate and run TEFCA Check for details.");
        else
            ToastService.ShowSuccess($"TEFCA check passed{(warned > 0 ? $" with {warned} warning(s)" : "")}.");
    }

    private static string TefcaColor(ConformanceOutcome outcome) => outcome switch
    {
        ConformanceOutcome.Pass => "#4caf50",
        ConformanceOutcome.Fail => "#e94560",
        ConformanceOutcome.Warning => "#ff9800",
        _ => "#666",
    };

    private string TefcaHeading()
    {
        if (tefcaResults == null) return "TEFCA Conformance";
        var failed = tefcaResults.Count(r => r.Outcome == ConformanceOutcome.Fail);
        var warned = tefcaResults.Count(r => r.Outcome == ConformanceOutcome.Warning);
        var summary = failed > 0 ? $"{failed} failed" : "passed";
        if (warned > 0) summary += $", {warned} warning(s)";
        return $"TEFCA Conformance ({summary})";
    }
}
