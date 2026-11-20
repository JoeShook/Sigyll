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
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;
using Sigyll.UI.Security;

namespace Sigyll.UI.Components.Pages;

public partial class Import
{
    [Inject] private CertificateImportService ImportService { get; set; } = null!;
    [Inject] private OperatorAccess Access { get; set; } = null!;

    protected override async Task OnInitializedAsync() => await Access.LoadAsync();

    private string certstorePath = string.Empty;
    private string pfxPassword = string.Empty;
    private bool isScanning;
    private bool isImporting;
    private List<ImportPreviewViewModel> previews = new();
    private List<(string trustDomain, int imported, List<string> errors)> importResults = new();

    // Passwords for single files the default password doesn't open, by full path. Kept for the page's lifetime so
    // a re-scan doesn't ask again; never stored anywhere else until the files are imported.
    private readonly Dictionary<string, string> filePasswords = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<string> passwordQueue = new();
    private bool passwordDialogHidden = true;
    private string? passwordFile;
    private string filePassword = string.Empty;
    private string? passwordError;

    protected override void OnInitialized()
    {
        // Default path to the PKI generator certstores
        var basePath = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                "_tests", "Udap.PKI.Generator", "certstores"));

        if (Directory.Exists(basePath))
        {
            certstorePath = basePath;
        }
    }

    private async Task ScanAsync()
    {
        isScanning = true;
        importResults.Clear();

        try
        {
            previews = await Task.Run(() => ImportService.ScanCertStoreAsync(certstorePath, pfxPassword, filePasswords));
        }
        finally
        {
            isScanning = false;
        }

        AskForPasswords(previews.SelectMany(p => p.FilesNeedingPassword));
    }

    /// <summary>Asks, one file at a time, for the password of each file the default password doesn't open.</summary>
    private void AskForPasswords(IEnumerable<string> files)
    {
        passwordQueue.Clear();
        foreach (var file in files)
            passwordQueue.Enqueue(file);
        AskNext();
    }

    private void AskNext()
    {
        filePassword = string.Empty;
        passwordError = null;
        if (passwordQueue.TryDequeue(out var file))
        {
            passwordFile = file;
            passwordDialogHidden = false;
        }
        else
        {
            passwordFile = null;
            passwordDialogHidden = true;
        }
    }

    private async Task UsePasswordAsync()
    {
        if (passwordFile == null) return;

        if (!CertificateImportService.Pkcs12Opens(passwordFile, filePassword))
        {
            passwordError = "Incorrect password. Try again.";
            filePassword = string.Empty;
            return;
        }

        filePasswords[passwordFile] = filePassword;
        await NextOrRescanAsync();
    }

    private Task SkipPasswordAsync() => NextOrRescanAsync();

    private async Task CancelPasswordsAsync()
    {
        passwordQueue.Clear();
        await NextOrRescanAsync();
    }

    /// <summary>The next file, or, after the last one, a new scan so the preview counts the files that now open.</summary>
    private async Task NextOrRescanAsync()
    {
        if (passwordQueue.Count > 0)
        {
            AskNext();
            return;
        }

        passwordDialogHidden = true;
        passwordFile = null;
        isScanning = true;
        try
        {
            previews = await Task.Run(() => ImportService.ScanCertStoreAsync(certstorePath, pfxPassword, filePasswords));
        }
        finally
        {
            isScanning = false;
        }
    }

    /// <summary>A file's path below the scanned folder, for the password prompt.</summary>
    private string DisplayPath(string? file) =>
        file == null ? string.Empty : Path.GetRelativePath(certstorePath, file);

    private async Task ImportSingleAsync(ImportPreviewViewModel preview)
    {
        isImporting = true;

        try
        {
            var (imported, errors) = await ImportService.ImportTrustDomainAsync(
                preview.DirectoryPath, pfxPassword, filePasswords);

            importResults.Add((preview.TrustDomainName, imported, errors));

            // Remove from preview list after import
            previews.Remove(preview);
        }
        finally
        {
            isImporting = false;
        }
    }

    private async Task ImportAllAsync()
    {
        isImporting = true;

        try
        {
            var toImport = previews.Where(p => p.IsValid).ToList();
            foreach (var preview in toImport)
            {
                var (imported, errors) = await ImportService.ImportTrustDomainAsync(
                    preview.DirectoryPath, pfxPassword, filePasswords);

                importResults.Add((preview.TrustDomainName, imported, errors));
                previews.Remove(preview);
                StateHasChanged();
            }
        }
        finally
        {
            isImporting = false;
        }
    }
}
