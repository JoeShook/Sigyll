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
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services.Audit;

namespace Sigyll.UI.Components.Pages;

/// <summary>The audit trail, read-only: every role that can view CA state can read it.</summary>
public partial class AuditLog : IDisposable
{
    private const int PageSize = 100;

    [Inject] private AuditTrail Audit { get; set; } = null!;
    [Inject] private Services.TimeDisplayService TimeDisplay { get; set; } = null!;

    private static readonly List<string> actionOptions = [string.Empty, .. AuditActions.All.Order()];

    private AuditPage? results;
    private string action = string.Empty;
    private string actor = string.Empty;
    private string text = string.Empty;
    private int skip;

    protected override async Task OnInitializedAsync()
    {
        TimeDisplay.OnChanged += StateHasChanged;
        await LoadAsync();
    }

    private async Task LoadAsync()
    {
        results = await Audit.SearchAsync(new AuditQuery(
            Action: action.Length == 0 ? null : action,
            Actor: actor,
            Text: text,
            Skip: skip,
            Take: PageSize));
    }

    private async Task SearchAsync()
    {
        skip = 0;
        await LoadAsync();
    }

    private async Task OnActionChanged(string? value)
    {
        action = value ?? string.Empty;
        await SearchAsync();
    }

    private async Task NewerAsync()
    {
        skip = Math.Max(0, skip - PageSize);
        await LoadAsync();
    }

    private async Task OlderAsync()
    {
        skip += PageSize;
        await LoadAsync();
    }

    /// <summary>Where the Explorer shows the certificate, while it still exists there.</summary>
    private static string? ExplorerLink(AuditEvent e) =>
        e is { EntityType: "CaCertificate" or "IssuedCertificate", TrustDomainId: { } td, Thumbprint: { Length: > 0 } thumbprint }
            && e.Action is not (AuditActions.CertificateDeleted or AuditActions.TrustDomainDeleted)
            ? $"/explorer/{td}?thumbprint={Uri.EscapeDataString(thumbprint)}"
            : null;

    public void Dispose() => TimeDisplay.OnChanged -= StateHasChanged;
}
