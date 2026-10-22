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
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;
using Sigyll.UI.Security;

namespace Sigyll.UI.Components.Pages;

/// <summary>
/// Stand-alone CSR generation from a certificate file. Nothing is written to the database and no
/// issuing CA is involved — the certificate lives only in this circuit's memory.
/// </summary>
public partial class CsrTool : IDisposable
{
    [Inject] private CsrGenerationService CsrGenService { get; set; } = null!;
    [Inject] private Pkcs12BundleService BundleService { get; set; } = null!;
    [Inject] private CertificateParsingService ParsingService { get; set; } = null!;
    [Inject] private CertificateImportService ImportService { get; set; } = null!;
    [Inject] private IDbContextFactory<SigyllDbContext> DbFactory { get; set; } = null!;
    [Inject] private IJSRuntime JS { get; set; } = null!;
    [Inject] private OperatorAccess Access { get; set; } = null!;

    public class TrustDomainChoice
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
    }

    // --- Step 2: assemble .p12 ---
    private byte[]? bundleCertBytes;
    private string? bundleCertName;
    private string? bundleKeyPem;
    private string? bundleKeyName;
    private readonly List<byte[]> bundleChain = new();
    private string bundleKeyPassphrase = string.Empty;
    private string bundleP12Password = string.Empty;
    private string bundleName = string.Empty;
    private bool isAssembling;
    private string? bundleError;
    private Pkcs12BundleResult? bundleResult;

    private List<TrustDomainChoice> trustDomains = new();
    private TrustDomainChoice? importTrustDomain;
    private bool isImporting;
    private string? importMessage;
    private bool importSucceeded;

    protected override async Task OnInitializedAsync()
    {
        await Access.LoadAsync();
        await using var db = await DbFactory.CreateDbContextAsync();
        trustDomains = await db.TrustDomains
            .Where(t => t.Enabled)
            .OrderBy(t => t.Name)
            .Select(t => new TrustDomainChoice { Id = t.Id, Name = t.Name })
            .ToListAsync();
    }

    private async Task OnSignedCertUploaded(IEnumerable<FluentInputFileEventArgs> files)
    {
        bundleError = null;
        var (bytes, name) = await ReadSingleUploadAsync(files);
        if (bytes == null) return;
        bundleCertBytes = bytes;
        bundleCertName = name;
        bundleResult = null;
        if (string.IsNullOrWhiteSpace(bundleName) && name != null)
            bundleName = Path.GetFileNameWithoutExtension(name);
    }

    private async Task OnKeyUploaded(IEnumerable<FluentInputFileEventArgs> files)
    {
        bundleError = null;
        var (bytes, name) = await ReadSingleUploadAsync(files);
        if (bytes == null) return;
        bundleKeyPem = System.Text.Encoding.UTF8.GetString(bytes);
        bundleKeyName = name;
        bundleResult = null;
    }

    private async Task OnChainUploaded(IEnumerable<FluentInputFileEventArgs> files)
    {
        bundleError = null;
        foreach (var file in files.Where(f => f.LocalFile != null))
        {
            try
            {
                bundleChain.Add(await File.ReadAllBytesAsync(file.LocalFile!.FullName));
            }
            catch (Exception ex)
            {
                bundleError = $"Failed to read '{file.Name}': {ex.Message}";
            }
            finally
            {
                try { file.LocalFile?.Delete(); } catch { /* best effort */ }
            }
        }
        bundleResult = null;
    }

    private async Task<(byte[]? Bytes, string? Name)> ReadSingleUploadAsync(IEnumerable<FluentInputFileEventArgs> files)
    {
        var file = files.FirstOrDefault(f => f.LocalFile != null && !string.IsNullOrEmpty(f.Name));
        if (file == null) return (null, null);
        try
        {
            return (await File.ReadAllBytesAsync(file.LocalFile!.FullName), file.Name);
        }
        catch (Exception ex)
        {
            bundleError = $"Failed to read '{file.Name}': {ex.Message}";
            return (null, null);
        }
        finally
        {
            try { file.LocalFile?.Delete(); } catch { /* best effort */ }
        }
    }

    private void AssembleBundle()
    {
        if (bundleCertBytes == null || bundleKeyPem == null) return;

        bundleError = null;
        importMessage = null;
        isAssembling = true;

        try
        {
            var result = BundleService.Assemble(
                bundleCertBytes, bundleCertName ?? "certificate",
                bundleKeyPem, bundleKeyPassphrase,
                bundleChain, bundleP12Password,
                string.IsNullOrWhiteSpace(bundleName) ? null : bundleName);

            if (result.Success)
            {
                bundleResult = result;
                bundleKeyPassphrase = string.Empty;
            }
            else
            {
                bundleResult = null;
                bundleError = result.Error;
            }
        }
        finally
        {
            isAssembling = false;
        }
    }

    private async Task DownloadBundleAsync()
    {
        if (bundleResult?.Pkcs12Bytes == null) return;
        await JS.InvokeVoidAsync("sigilDownloadBase64",
            bundleResult.SuggestedFileName,
            Convert.ToBase64String(bundleResult.Pkcs12Bytes),
            "application/x-pkcs12");
    }

    /// <summary>
    /// Imports the assembled bundle into a trust domain. Chain certificates go in first (as
    /// trust-only CAs) so the leaf can resolve its issuer; the leaf then lands with its key.
    /// </summary>
    private async Task ImportBundleAsync()
    {
        if (bundleResult?.Pkcs12Bytes == null || importTrustDomain == null) return;

        isImporting = true;
        importMessage = null;
        importSucceeded = false;

        try
        {
            var chainNotes = new List<string>();
            var index = 0;
            foreach (var der in bundleResult.ChainDer)
            {
                index++;
                var parsedChain = ParsingService.Parse(der, $"chain-{index}.cer");
                if (parsedChain == null) continue;
                try
                {
                    var chainName = parsedChain.Certificate.GetNameInfo(X509NameType.SimpleName, false);
                    var r = await ImportService.ImportParsedCertificateAsync(parsedChain, importTrustDomain.Id, name: chainName);
                    if (r.Success && !r.AlreadyExists) chainNotes.Add($"added CA '{r.ImportedName}'");
                }
                finally
                {
                    parsedChain.Certificate.Dispose();
                }
            }

            var fileName = bundleResult.SuggestedFileName;
            var parsed = ParsingService.Parse(bundleResult.Pkcs12Bytes, fileName, bundleP12Password);
            if (parsed == null)
            {
                importMessage = "The assembled bundle could not be re-read for import.";
                return;
            }

            try
            {
                var result = await ImportService.ImportParsedCertificateAsync(
                    parsed, importTrustDomain.Id,
                    name: Path.GetFileNameWithoutExtension(fileName),
                    password: bundleP12Password);

                if (result.NeedsCaSelection)
                {
                    importMessage = $"The issuing CA ('{parsed.Certificate.Issuer}') is not in trust domain '{importTrustDomain.Name}'. " +
                                    "Add the CA's certificate chain to Step 2 and rebuild, or import the chain into the trust domain first.";
                }
                else if (result.Success)
                {
                    importSucceeded = true;
                    var suffix = chainNotes.Count > 0 ? $" ({string.Join(", ", chainNotes)})" : "";
                    importMessage = result.AlreadyExists
                        ? $"'{result.ImportedName}' already existed in '{importTrustDomain.Name}'; private key merged.{suffix}"
                        : $"Imported '{result.ImportedName}' into '{importTrustDomain.Name}' with its private key.{suffix}";
                }
                else
                {
                    importMessage = result.Error ?? "Import failed.";
                }
            }
            finally
            {
                parsed.Certificate.Dispose();
            }
        }
        catch (Exception ex)
        {
            importMessage = $"Import failed: {ex.Message}";
        }
        finally
        {
            isImporting = false;
        }
    }

    private void ResetBundle()
    {
        bundleCertBytes = null;
        bundleCertName = null;
        bundleKeyPem = null;
        bundleKeyName = null;
        bundleChain.Clear();
        bundleKeyPassphrase = string.Empty;
        bundleP12Password = string.Empty;
        bundleName = string.Empty;
        bundleError = null;
        bundleResult = null;
        importMessage = null;
        importSucceeded = false;
    }

    // --- Step 1: CSR from file ---
    private byte[]? uploadedBytes;
    private string? uploadedName;
    private string serverPath = string.Empty;
    private string password = string.Empty;
    private bool isLoading;
    private string? loadError;

    private X509Certificate2? loadedCert;
    private string loadedName = string.Empty;

    private async Task OnFileUploaded(IEnumerable<FluentInputFileEventArgs> files)
    {
        loadError = null;
        var file = files.FirstOrDefault(f => f.LocalFile != null && !string.IsNullOrEmpty(f.Name));
        if (file == null) return;

        try
        {
            uploadedBytes = await File.ReadAllBytesAsync(file.LocalFile!.FullName);
            uploadedName = file.Name;
            Clear();
        }
        catch (Exception ex)
        {
            loadError = $"Failed to read '{file.Name}': {ex.Message}";
        }
        finally
        {
            try { file.LocalFile?.Delete(); } catch { /* temp file — best effort */ }
        }
    }

    private async Task LoadAsync()
    {
        loadError = null;
        isLoading = true;
        StateHasChanged();

        try
        {
            byte[] bytes;
            string name;

            if (uploadedBytes != null)
            {
                bytes = uploadedBytes;
                name = uploadedName ?? "certificate";
            }
            else
            {
                var path = serverPath.Trim().Trim('"');
                if (!File.Exists(path))
                {
                    loadError = $"File not found on the server: {path}";
                    return;
                }
                bytes = await File.ReadAllBytesAsync(path);
                name = Path.GetFileName(path);
            }

            var cert = LoadCertificate(bytes, name, password);
            Clear();
            loadedCert = cert;
            loadedName = Path.GetFileNameWithoutExtension(name);
        }
        catch (Exception ex)
        {
            loadError = ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("MAC", StringComparison.OrdinalIgnoreCase)
                ? "Could not open the PKCS#12 file — check the password."
                : $"Could not read the certificate: {ex.Message}";
        }
        finally
        {
            isLoading = false;
        }
    }

    private static X509Certificate2 LoadCertificate(byte[] bytes, string fileName, string password)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

        if (ext is ".pfx" or ".p12")
            return X509CertificateLoader.LoadPkcs12(bytes, password, flags);

        if (ext is ".cer" or ".crt" or ".der" or ".pem")
        {
            try { return X509CertificateLoader.LoadCertificate(bytes); }
            catch { return X509Certificate2.CreateFromPem(System.Text.Encoding.UTF8.GetString(bytes)); }
        }

        // Unknown extension: PKCS#12 first (the primary use case), then DER/PEM
        try { return X509CertificateLoader.LoadPkcs12(bytes, password, flags); }
        catch
        {
            try { return X509CertificateLoader.LoadCertificate(bytes); }
            catch { return X509Certificate2.CreateFromPem(System.Text.Encoding.UTF8.GetString(bytes)); }
        }
    }

    private Task<CsrGenerationResult> GenerateAsync(CsrGenerationRequest request)
    {
        if (loadedCert == null)
            return Task.FromResult(CsrGenerationResult.Failure("No certificate loaded."));

        return Task.FromResult(CsrGenService.GenerateCsrFromCertificate(loadedCert, loadedName, request));
    }

    private void Clear()
    {
        loadedCert?.Dispose();
        loadedCert = null;
        loadedName = string.Empty;
    }

    public void Dispose() => Clear();
}
