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
using Sigyll.Common.Services.Export;

namespace Sigyll.UI.Components.SettingsSections;

public partial class VaultExportSettingsCard
{
    [Inject] private VaultExportService VaultExport { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;
    [Inject] private Services.TimeDisplayService TimeDisplay { get; set; } = null!;

    private bool isLoading = true;
    private bool enabled;
    private string? address;
    private string? mount;
    private string? updatedBy;
    private DateTime updatedAt;
    private string? settingsError;
    private List<TrustDomainRow> trustDomains = new();

    protected override async Task OnInitializedAsync()
    {
        var settings = await VaultExport.GetSettingsAsync();
        enabled = settings.Enabled;
        address = settings.Address;
        mount = settings.Mount;
        updatedBy = settings.UpdatedBy;
        updatedAt = settings.UpdatedAt;
        await LoadTrustDomainsAsync();
        isLoading = false;
    }

    private async Task LoadTrustDomainsAsync()
    {
        trustDomains = (await VaultExport.GetTrustDomainVaultSettingsAsync())
            .Select(t => new TrustDomainRow
            {
                TrustDomainId = t.TrustDomainId,
                TrustDomainName = t.TrustDomainName,
                Original = t.Namespace,
                Editable = t.Namespace,
                BackupEnabled = t.BackupEnabled,
                LastBackupAt = t.LastBackupAt,
                LastBackupBy = t.LastBackupBy,
            })
            .ToList();
    }

    private async Task SaveSettingsAsync()
    {
        try
        {
            var saved = await VaultExport.SaveSettingsAsync(enabled, address, mount);
            address = saved.Address;
            mount = saved.Mount;
            updatedBy = saved.UpdatedBy;
            updatedAt = saved.UpdatedAt;
            settingsError = null;
            ToastService.ShowSuccess(enabled ? "Export to Vault is on." : "Export to Vault is off.");
        }
        catch (ArgumentException ex)
        {
            settingsError = ex.Message;
        }
    }

    private async Task SaveNamespaceAsync(TrustDomainRow row)
    {
        try
        {
            await VaultExport.SetTrustDomainNamespaceAsync(row.TrustDomainId, row.Editable);
            ToastService.ShowSuccess($"Trust domain {row.TrustDomainName} now exports to {(string.IsNullOrWhiteSpace(row.Editable) ? "a namespace chosen on its next export" : row.Editable)}.");
            await LoadTrustDomainsAsync();
        }
        catch (ArgumentException ex)
        {
            row.Error = ex.Message;
        }
    }

    private async Task SetBackupAsync(TrustDomainRow row, bool value)
    {
        try
        {
            await VaultExport.SetTrustDomainBackupAsync(row.TrustDomainId, value);
            row.BackupEnabled = value;
            row.Error = null;
            ToastService.ShowSuccess($"Full backup to Vault is {(value ? "on" : "off")} for {row.TrustDomainName}.");
        }
        catch (ArgumentException ex)
        {
            row.Error = ex.Message;
        }
    }

    private class TrustDomainRow
    {
        public int TrustDomainId { get; init; }
        public string TrustDomainName { get; init; } = "";
        public string? Original { get; init; }
        public string? Editable { get; set; }
        public bool BackupEnabled { get; set; }
        public DateTime? LastBackupAt { get; init; }
        public string? LastBackupBy { get; init; }
        public string? Error { get; set; }
    }
}
