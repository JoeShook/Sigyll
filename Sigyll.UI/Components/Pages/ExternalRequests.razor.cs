#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components;
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.JSInterop;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;
using Sigyll.UI.Services;

namespace Sigyll.UI.Components.Pages;

public partial class ExternalRequests
{
    [Inject] private ExternalCertificateRequestService RequestService { get; set; } = null!;
    [Inject] private IDbContextFactory<SigyllDbContext> DbFactory { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;
    [Inject] private IJSRuntime JS { get; set; } = null!;
    [Inject] private TimeDisplayService TimeDisplay { get; set; } = null!;

    public class TrustDomainChoice { public int Id { get; set; } public string Name { get; set; } = string.Empty; }
    public class CaChoice { public int Id { get; set; } public string Name { get; set; } = string.Empty; }
    public class SanRow { public SanType Type { get; set; } = SanType.Uri; public string Value { get; set; } = string.Empty; }

    public class ModelOption
    {
        public int? Id { get; set; }
        public string? EntityType { get; set; }
        public string Label { get; set; } = string.Empty;
        public string? Pem { get; set; }
        public static readonly ModelOption None = new() { Label = "(none — start from scratch)" };
    }

    private static readonly string[] keyAlgorithmOptions = ["RSA", "ECDSA"];
    private static readonly string[] rsaKeySizes = ["2048", "3072", "4096"];
    private static readonly string[] ecdsaKeySizes = ["256", "384", "521"];
    private static readonly SanType[] sanTypeOptions = Enum.GetValues<SanType>();
    private static readonly CsrExtensionProfile[] allProfiles = Enum.GetValues<CsrExtensionProfile>();

    // list state
    private List<TrustDomainChoice> trustDomains = new();
    private TrustDomainChoice? selectedTrustDomain;
    private bool showCompleted;
    private bool isLoading = true;
    private List<ExternalCertificateRequestSummary> requests = new();

    // new request dialog
    private bool newDialogHidden = true;
    private bool isCreating;
    private string newName = string.Empty;
    private string newSubjectDn = string.Empty;
    private List<SanRow> newSans = new();
    private string newKeyAlgorithm = "RSA";
    private string newKeySize = "2048";
    private CsrExtensionProfile newProfile = CsrExtensionProfile.UdapClient;
    private string newExternalCaName = string.Empty;
    private string newNotes = string.Empty;
    private List<ModelOption> modelOptions = new() { ModelOption.None };
    private ModelOption selectedModel = ModelOption.None;
    private ExternalCertificateRequestResult? createResult;

    // edit mode (same dialog): the request being edited, and whether to rotate its key
    private int? editingId;
    private bool editRegenerateKey;
    private string editCurrentKey = string.Empty;
    private bool editHasModel;

    // complete dialog
    private bool completeDialogHidden = true;
    private bool isCompleting;
    private ExternalCertificateRequestSummary? completeTarget;
    private byte[]? completeCertBytes;
    private string? completeCertName;
    private readonly List<byte[]> completeChain = new();
    private FulfillExternalRequestResult? completeResult;
    private List<CaChoice> caChoices = new();
    private CaChoice? selectedIssuingCa;

    // download .p12 dialog
    private bool p12DialogHidden = true;
    private ExternalCertificateRequestSummary? p12Target;
    private string p12Password = string.Empty;
    private bool p12IncludeChain = true;

    // export key dialog
    private bool exportKeyDialogHidden = true;
    private ExternalCertificateRequestSummary? exportKeyTarget;
    private string exportKeyPassphrase = string.Empty;

    private string[] KeySizeOptions => newKeyAlgorithm == "ECDSA" ? ecdsaKeySizes : rsaKeySizes;

    private CsrExtensionProfile[] ProfileOptions => selectedModel.Id != null || editHasModel
        ? allProfiles
        : allProfiles.Where(p => p != CsrExtensionProfile.FromModeledCertificate).ToArray();

    private static string ProfileLabel(CsrExtensionProfile p) => p switch
    {
        CsrExtensionProfile.None => "None (SANs only)",
        CsrExtensionProfile.UdapClient => "UDAP client — KU digitalSignature, EKU clientAuth",
        CsrExtensionProfile.TlsServer => "TLS server — KU digitalSignature+keyEncipherment, EKU serverAuth",
        CsrExtensionProfile.TlsServerAndClient => "TLS server + client",
        CsrExtensionProfile.FromModeledCertificate => "Copy from the modeled certificate",
        _ => p.ToString()
    };

    private static string SanPlaceholder(SanType type) => type switch
    {
        SanType.Uri => "https://example.com/fhir/r4",
        SanType.Dns => "example.com",
        SanType.Email => "admin@example.com",
        SanType.IpAddress => "192.168.1.1",
        _ => string.Empty
    };

    // ------------------------------------------------------------------ lifecycle

    protected override async Task OnInitializedAsync()
    {
        await using var db = await DbFactory.CreateDbContextAsync();
        trustDomains = await db.TrustDomains
            .Where(t => t.Enabled)
            .OrderBy(t => t.Name)
            .Select(t => new TrustDomainChoice { Id = t.Id, Name = t.Name })
            .ToListAsync();

        selectedTrustDomain = trustDomains.FirstOrDefault();
        await LoadRequestsAsync();
    }

    private async Task LoadRequestsAsync()
    {
        isLoading = true;
        try
        {
            requests = await RequestService.ListAsync(selectedTrustDomain?.Id, showCompleted);
        }
        finally
        {
            isLoading = false;
        }
    }

    private async Task OnTrustDomainChanged(TrustDomainChoice? choice)
    {
        selectedTrustDomain = choice;
        await LoadRequestsAsync();
    }

    private async Task OnShowCompletedChanged(bool value)
    {
        showCompleted = value;
        await LoadRequestsAsync();
    }

    // ------------------------------------------------------------------ new request

    private async Task ShowNewRequestDialog()
    {
        if (selectedTrustDomain == null) return;

        editingId = null;
        editRegenerateKey = false;
        editHasModel = false;
        createResult = null;
        isCreating = false;
        newName = string.Empty;
        newSubjectDn = string.Empty;
        newSans = new List<SanRow> { new() };
        newKeyAlgorithm = "RSA";
        newKeySize = "2048";
        newProfile = CsrExtensionProfile.UdapClient;
        newExternalCaName = string.Empty;
        newNotes = string.Empty;
        selectedModel = ModelOption.None;

        await using var db = await DbFactory.CreateDbContextAsync();
        var tdId = selectedTrustDomain.Id;

        var cas = await db.CaCertificates
            .Where(c => c.TrustDomainId == tdId && !c.IsArchived)
            .OrderBy(c => c.Name)
            .Select(c => new ModelOption { Id = c.Id, EntityType = "CaCertificate", Label = "[CA] " + c.Name, Pem = c.X509CertificatePem })
            .ToListAsync();
        var issued = await db.IssuedCertificates
            .Where(i => i.IssuingCaCertificate.TrustDomainId == tdId && !i.IsArchived)
            .OrderBy(i => i.Name)
            .Select(i => new ModelOption { Id = i.Id, EntityType = "IssuedCertificate", Label = i.Name, Pem = i.X509CertificatePem })
            .ToListAsync();

        modelOptions = new List<ModelOption> { ModelOption.None };
        modelOptions.AddRange(issued);
        modelOptions.AddRange(cas);

        newDialogHidden = false;
    }

    private void OnModelSelected(ModelOption? option)
    {
        selectedModel = option ?? ModelOption.None;
        if (selectedModel.Id == null || string.IsNullOrEmpty(selectedModel.Pem))
        {
            if (newProfile == CsrExtensionProfile.FromModeledCertificate)
                newProfile = CsrExtensionProfile.UdapClient;
            return;
        }

        try
        {
            using var cert = X509Certificate2.CreateFromPem(selectedModel.Pem);
            newSubjectDn = cert.Subject;
            newSans = CsrGenerationService.ExtractSubjectAltNames(cert)
                .Select(s => new SanRow { Type = s.Type, Value = s.Value })
                .ToList();
            if (newSans.Count == 0) newSans.Add(new SanRow());

            var ecdsa = cert.GetECDsaPublicKey();
            newKeyAlgorithm = ecdsa != null ? "ECDSA" : "RSA";
            var size = (ecdsa?.KeySize ?? cert.GetRSAPublicKey()?.KeySize ?? 2048).ToString();
            newKeySize = KeySizeOptions.Contains(size) ? size : KeySizeOptions[0];

            newProfile = CsrExtensionProfile.FromModeledCertificate;
            if (string.IsNullOrWhiteSpace(newName))
                newName = selectedModel.Label.Replace("[CA] ", "") + " (renewal)";
        }
        catch (Exception ex)
        {
            ToastService.ShowError($"Could not read the selected certificate: {ex.Message}");
        }
    }

    private void OnKeyAlgorithmChanged(string? algorithm)
    {
        newKeyAlgorithm = algorithm ?? "RSA";
        if (!KeySizeOptions.Contains(newKeySize)) newKeySize = KeySizeOptions[0];
    }

    private bool NewRequestInvalid =>
        isCreating
        || string.IsNullOrWhiteSpace(newName)
        || string.IsNullOrWhiteSpace(newSubjectDn)
        || newSans.Any(s => !string.IsNullOrWhiteSpace(s.Value) && !IsValidSan(s));

    private static bool IsValidSan(SanRow san) => san.Type switch
    {
        SanType.Uri => Uri.TryCreate(san.Value.Trim(), UriKind.Absolute, out _),
        SanType.IpAddress => System.Net.IPAddress.TryParse(san.Value.Trim(), out _),
        SanType.Email => san.Value.Contains('@'),
        _ => true
    };

    /// <summary>Opens the request dialog in edit mode, pre-filled from the pending request.</summary>
    private void ShowEditDialog(ExternalCertificateRequestSummary row)
    {
        editingId = row.Id;
        editRegenerateKey = false;
        editCurrentKey = $"{row.KeyAlgorithm} {row.KeySize}";
        editHasModel = row.ModeledOnCertificateId != null;
        createResult = null;
        isCreating = false;

        newName = row.Name;
        newSubjectDn = row.SubjectDn;
        newSans = row.SubjectAltNames.Select(s => new SanRow { Type = s.Type, Value = s.Value }).ToList();
        if (newSans.Count == 0) newSans.Add(new SanRow());
        newKeyAlgorithm = row.KeyAlgorithm == "ECDSA" ? "ECDSA" : "RSA";
        var size = row.KeySize.ToString();
        newKeySize = KeySizeOptions.Contains(size) ? size : KeySizeOptions[0];
        newProfile = row.Profile;
        newExternalCaName = row.ExternalCaName ?? string.Empty;
        newNotes = row.Notes ?? string.Empty;
        selectedModel = ModelOption.None;

        newDialogHidden = false;
    }

    private async Task CreateRequestAsync()
    {
        if (NewRequestInvalid || (editingId == null && selectedTrustDomain == null)) return;

        isCreating = true;
        try
        {
            if (editingId is int editId)
            {
                var updated = await RequestService.UpdateAsync(new UpdateExternalCertificateRequest
                {
                    Id = editId,
                    Name = newName,
                    SubjectDn = newSubjectDn,
                    SubjectAltNames = newSans.Where(s => !string.IsNullOrWhiteSpace(s.Value))
                        .Select(s => new SanEntry(s.Type, s.Value.Trim())).ToList(),
                    Profile = newProfile,
                    ExternalCaName = newExternalCaName,
                    Notes = newNotes,
                    RegenerateKey = editRegenerateKey,
                    KeyAlgorithm = newKeyAlgorithm,
                    KeySize = int.TryParse(newKeySize, out var newSize) ? newSize : 2048
                });

                if (updated.Success)
                {
                    createResult = updated;
                    await LoadRequestsAsync();
                }
                else
                {
                    ToastService.ShowError(updated.Error ?? "Could not update the request.");
                }
                return;
            }

            var result = await RequestService.CreateAsync(new CreateExternalCertificateRequest
            {
                TrustDomainId = selectedTrustDomain.Id,
                Name = newName,
                SubjectDn = newSubjectDn,
                SubjectAltNames = newSans.Where(s => !string.IsNullOrWhiteSpace(s.Value))
                    .Select(s => new SanEntry(s.Type, s.Value.Trim())).ToList(),
                KeyAlgorithm = newKeyAlgorithm,
                KeySize = int.TryParse(newKeySize, out var size) ? size : 2048,
                Profile = newProfile,
                ModeledOnCertificateId = selectedModel.Id,
                ModeledOnEntityType = selectedModel.EntityType,
                ExternalCaName = newExternalCaName,
                Notes = newNotes
            });

            if (result.Success)
            {
                createResult = result;
                await LoadRequestsAsync();
            }
            else
            {
                ToastService.ShowError(result.Error ?? "Could not create the request.");
            }
        }
        finally
        {
            isCreating = false;
        }
    }

    private async Task DownloadCreatedCsrAsync()
    {
        if (createResult?.RequestId is not int id) return;
        var row = requests.FirstOrDefault(r => r.Id == id);
        if (row != null) await DownloadCsrAsync(row);
    }

    private async Task CopyCreatedCsrAsync()
    {
        if (createResult?.CsrPem == null) return;
        await JS.InvokeVoidAsync("sigilCopyText", createResult.CsrPem);
        ToastService.ShowSuccess("CSR copied to clipboard");
    }

    // ------------------------------------------------------------------ row actions

    private async Task DownloadCsrAsync(ExternalCertificateRequestSummary row)
    {
        var export = await RequestService.ExportCsrAsync(row.Id);
        if (!export.Success) { ToastService.ShowError(export.Error ?? "Export failed."); return; }
        await JS.InvokeVoidAsync("sigilDownloadText", export.FileName, export.Content, export.ContentType);
    }

    private async Task CopyCsrAsync(ExternalCertificateRequestSummary row)
    {
        var export = await RequestService.ExportCsrAsync(row.Id);
        if (!export.Success) { ToastService.ShowError(export.Error ?? "Export failed."); return; }
        await JS.InvokeVoidAsync("sigilCopyText", export.Content);
        ToastService.ShowSuccess($"CSR for '{row.Name}' copied to clipboard");
    }

    private void ShowP12Dialog(ExternalCertificateRequestSummary row)
    {
        p12Target = row;
        p12Password = string.Empty;
        p12IncludeChain = true;
        p12DialogHidden = false;
    }

    private async Task DownloadP12Async()
    {
        if (p12Target == null) return;
        var export = await RequestService.ExportPkcs12Async(p12Target.Id, p12Password, p12IncludeChain);
        p12Password = string.Empty;
        p12DialogHidden = true;
        if (!export.Success || export.Bytes == null) { ToastService.ShowError(export.Error ?? "Export failed."); return; }
        await JS.InvokeVoidAsync("sigilDownloadBase64", export.FileName, Convert.ToBase64String(export.Bytes), export.ContentType);
    }

    private void ShowExportKeyDialog(ExternalCertificateRequestSummary row)
    {
        exportKeyTarget = row;
        exportKeyPassphrase = string.Empty;
        exportKeyDialogHidden = false;
    }

    private async Task ExportKeyAsync()
    {
        if (exportKeyTarget == null) return;
        var export = await RequestService.ExportPrivateKeyAsync(exportKeyTarget.Id, exportKeyPassphrase);
        exportKeyPassphrase = string.Empty;
        exportKeyDialogHidden = true;
        if (!export.Success) { ToastService.ShowError(export.Error ?? "Export failed."); return; }
        await JS.InvokeVoidAsync("sigilDownloadText", export.FileName, export.Content, export.ContentType);
        ToastService.ShowWarning($"Private key for '{exportKeyTarget.Name}' exported — keep the file and passphrase safe.");
    }

    private async Task CancelAsync(ExternalCertificateRequestSummary row)
    {
        if (await RequestService.CancelAsync(row.Id))
        {
            ToastService.ShowSuccess($"Cancelled '{row.Name}'. Its key is kept until you delete the request.");
            await LoadRequestsAsync();
        }
    }

    private async Task DeleteAsync(ExternalCertificateRequestSummary row)
    {
        if (row.Status == ExternalRequestStatus.Pending)
        {
            var confirmed = await JS.InvokeAsync<bool>("confirm",
                $"Delete '{row.Name}'? This permanently destroys its stored private key; a certificate the CA returns for this CSR will be unusable.");
            if (!confirmed) return;
        }

        if (await RequestService.DeleteAsync(row.Id))
        {
            ToastService.ShowSuccess($"Deleted '{row.Name}'.");
            await LoadRequestsAsync();
        }
    }

    // ------------------------------------------------------------------ complete

    private async Task ShowCompleteDialog(ExternalCertificateRequestSummary row)
    {
        completeTarget = row;
        completeCertBytes = null;
        completeCertName = null;
        completeChain.Clear();
        completeResult = null;
        selectedIssuingCa = null;
        isCompleting = false;

        await using var db = await DbFactory.CreateDbContextAsync();
        caChoices = await db.CaCertificates
            .Where(c => c.TrustDomainId == row.TrustDomainId && !c.IsArchived)
            .OrderBy(c => c.Name)
            .Select(c => new CaChoice { Id = c.Id, Name = c.Name })
            .ToListAsync();

        completeDialogHidden = false;
    }

    private async Task OnSignedCertUploaded(IEnumerable<FluentInputFileEventArgs> files)
    {
        var file = files.FirstOrDefault(f => f.LocalFile != null && !string.IsNullOrEmpty(f.Name));
        if (file == null) return;
        try
        {
            completeCertBytes = await File.ReadAllBytesAsync(file.LocalFile!.FullName);
            completeCertName = file.Name;
            completeResult = null;
        }
        catch (Exception ex)
        {
            ToastService.ShowError($"Failed to read '{file.Name}': {ex.Message}");
        }
        finally
        {
            try { file.LocalFile?.Delete(); } catch { /* best effort */ }
        }
    }

    private async Task OnChainUploaded(IEnumerable<FluentInputFileEventArgs> files)
    {
        foreach (var file in files.Where(f => f.LocalFile != null))
        {
            try { completeChain.Add(await File.ReadAllBytesAsync(file.LocalFile!.FullName)); }
            catch (Exception ex) { ToastService.ShowError($"Failed to read '{file.Name}': {ex.Message}"); }
            finally { try { file.LocalFile?.Delete(); } catch { /* best effort */ } }
        }
        if (completeResult?.NeedsCaSelection == true) completeResult = null;
    }

    private async Task CompleteRequestAsync()
    {
        if (completeTarget == null || completeCertBytes == null) return;

        isCompleting = true;
        try
        {
            completeResult = await RequestService.FulfillAsync(
                completeTarget.Id, completeCertBytes, completeCertName ?? "certificate.cer",
                completeChain, selectedIssuingCa?.Id);

            if (completeResult.Success)
            {
                ToastService.ShowSuccess($"'{completeResult.ImportedName}' imported with its private key.");
                await LoadRequestsAsync();
            }
        }
        catch (Exception ex)
        {
            completeResult = FulfillExternalRequestResult.Failure($"Import failed: {ex.Message}");
        }
        finally
        {
            isCompleting = false;
        }
    }

    private void CloseCompleteDialog()
    {
        completeDialogHidden = true;
        completeCertBytes = null;
        completeChain.Clear();
        completeResult = null;
    }
}
