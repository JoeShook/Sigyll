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
using Microsoft.FluentUI.AspNetCore.Components;
using Microsoft.JSInterop;
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;

namespace Sigyll.UI.Components.Shared;

public partial class CsrBuilder
{
    [Inject] private IJSRuntime JS { get; set; } = null!;
    [Inject] private IToastService ToastService { get; set; } = null!;

    /// <summary>The certificate the CSR is modeled on (public part is enough for new-key mode).</summary>
    [Parameter, EditorRequired] public X509Certificate2 Certificate { get; set; } = null!;

    /// <summary>Whether a private key is available to sign the CSR with (stored in Sigyll or inside the uploaded .p12).</summary>
    [Parameter] public bool HasPrivateKey { get; set; }

    /// <summary>Display name of the source (certificate name or file name).</summary>
    [Parameter] public string SourceName { get; set; } = string.Empty;

    /// <summary>
    /// Performs the generation. The component fills in key mode, subject, SANs and extension
    /// options; the parent decides whether that means a stored certificate or an in-memory one.
    /// </summary>
    [Parameter, EditorRequired] public Func<CsrGenerationRequest, Task<CsrGenerationResult>> Generate { get; set; } = null!;

    /// <summary>Raised by Cancel/Close. Buttons are only rendered when a handler is attached.</summary>
    [Parameter] public EventCallback OnClose { get; set; }

    /// <summary>
    /// Key choice the form starts with. Reuse is only honoured when a private key is available;
    /// otherwise the form falls back to generating a new key pair.
    /// </summary>
    [Parameter] public CsrKeyMode DefaultKeyMode { get; set; } = CsrKeyMode.ReuseExistingKey;

    public class EditableSan
    {
        public SanType Type { get; set; } = SanType.Uri;
        public string Value { get; set; } = string.Empty;
    }

    private static readonly string[] keyModeOptions = ["reuse", "new"];
    private static readonly string[] keyAlgorithmOptions = ["RSA", "ECDSA"];
    private static readonly string[] rsaKeySizes = ["2048", "3072", "4096"];
    private static readonly string[] ecdsaKeySizes = ["256", "384", "521"];
    private static readonly SanType[] sanTypeOptions = Enum.GetValues<SanType>();

    private string? initializedForThumbprint;
    private bool isGenerating;
    private string keyMode = "reuse";
    private string newKeyAlgorithm = "RSA";
    private string newKeySize = "2048";
    private string newKeyPassphrase = string.Empty;
    private string subjectDn = string.Empty;
    private List<EditableSan> sans = new();
    private List<(SanType Type, string Value)> originalSans = new();
    private bool includeExtensions = true;
    private CsrGenerationResult? result;

    private string[] KeySizeOptions => newKeyAlgorithm == "ECDSA" ? ecdsaKeySizes : rsaKeySizes;

    protected override void OnParametersSet()
    {
        // Re-seed the form whenever a different certificate is supplied
        if (Certificate != null && !string.Equals(initializedForThumbprint, Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            initializedForThumbprint = Certificate.Thumbprint;
            ResetForm();
        }
    }

    private void ResetForm()
    {
        result = null;
        isGenerating = false;
        newKeyPassphrase = string.Empty;
        includeExtensions = true;
        subjectDn = Certificate.Subject;

        var ecdsa = Certificate.GetECDsaPublicKey();
        newKeyAlgorithm = ecdsa != null ? "ECDSA" : "RSA";
        var existingSize = (ecdsa?.KeySize ?? Certificate.GetRSAPublicKey()?.KeySize ?? 2048).ToString();
        newKeySize = KeySizeOptions.Contains(existingSize) ? existingSize : KeySizeOptions[0];

        keyMode = HasPrivateKey && DefaultKeyMode == CsrKeyMode.ReuseExistingKey ? "reuse" : "new";

        sans = CsrGenerationService.ExtractSubjectAltNames(Certificate)
            .Select(s => new EditableSan { Type = s.Type, Value = s.Value })
            .ToList();
        originalSans = sans.Select(s => (s.Type, s.Value.Trim())).ToList();
    }

    private void StartOver() => ResetForm();

    private void OnKeyAlgorithmChanged(string? algorithm)
    {
        newKeyAlgorithm = algorithm ?? "RSA";
        if (!KeySizeOptions.Contains(newKeySize))
            newKeySize = KeySizeOptions[0];
    }

    private bool FormInvalid =>
        isGenerating
        || string.IsNullOrWhiteSpace(subjectDn)
        || (keyMode == "new" && string.IsNullOrWhiteSpace(newKeyPassphrase))
        || (keyMode == "reuse" && !HasPrivateKey)
        || sans.Any(s => !string.IsNullOrWhiteSpace(s.Value) && !IsValidSan(s));

    private static bool IsValidSan(EditableSan san) => san.Type switch
    {
        SanType.Uri => Uri.TryCreate(san.Value.Trim(), UriKind.Absolute, out _),
        SanType.IpAddress => System.Net.IPAddress.TryParse(san.Value.Trim(), out _),
        SanType.Email => san.Value.Contains('@'),
        _ => true
    };

    private static string SanPlaceholder(SanType type) => type switch
    {
        SanType.Uri => "https://example.com/fhir/r4",
        SanType.Dns => "example.com",
        SanType.Email => "admin@example.com",
        SanType.IpAddress => "192.168.1.1",
        _ => string.Empty
    };

    private string DescribeCurrentKey()
    {
        var rsa = Certificate.GetRSAPublicKey();
        if (rsa != null) return $"RSA {rsa.KeySize}-bit";
        var ecdsa = Certificate.GetECDsaPublicKey();
        if (ecdsa != null) return $"ECDSA {ecdsa.KeySize}-bit";
        return "Unknown";
    }

    private async Task GenerateAsync()
    {
        if (FormInvalid) return;

        isGenerating = true;
        StateHasChanged();

        try
        {
            // Untouched SAN list ⇒ copy the certificate's SAN extension verbatim (keeps otherName etc.)
            var edited = sans
                .Where(s => !string.IsNullOrWhiteSpace(s.Value))
                .Select(s => (s.Type, s.Value.Trim()))
                .ToList();
            var unchanged = edited.SequenceEqual(originalSans);

            var request = new CsrGenerationRequest
            {
                KeyMode = keyMode == "new" ? CsrKeyMode.GenerateNewKey : CsrKeyMode.ReuseExistingKey,
                NewKeyAlgorithm = newKeyAlgorithm,
                NewKeySize = int.TryParse(newKeySize, out var size) ? size : 2048,
                NewKeyPassphrase = keyMode == "new" ? newKeyPassphrase : null,
                SubjectDn = subjectDn,
                SubjectAltNames = unchanged ? null : edited.Select(s => new SanEntry(s.Type, s.Item2)).ToList(),
                IncludeExistingExtensions = includeExtensions
            };

            var generated = await Generate(request);
            if (generated.Success)
            {
                result = generated;
                newKeyPassphrase = string.Empty;
            }
            else
            {
                ToastService.ShowError(generated.Error ?? "CSR generation failed.");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowError($"CSR generation failed: {ex.Message}");
        }
        finally
        {
            isGenerating = false;
            StateHasChanged();
        }
    }

    private async Task CopyCsrAsync()
    {
        if (result?.CsrPem == null) return;
        await JS.InvokeVoidAsync("sigilCopyText", result.CsrPem);
        ToastService.ShowSuccess("CSR copied to clipboard (PEM)");
    }

    private async Task DownloadCsrAsync()
    {
        if (result?.CsrPem == null) return;
        await JS.InvokeVoidAsync("sigilDownloadText", result.SuggestedFileName, result.CsrPem, "application/pkcs10");
    }

    private async Task DownloadPrivateKeyAsync()
    {
        if (result?.EncryptedPrivateKeyPem == null) return;
        var keyFile = Path.ChangeExtension(result.SuggestedFileName, ".key");
        await JS.InvokeVoidAsync("sigilDownloadText", keyFile, result.EncryptedPrivateKeyPem, "application/x-pem-file");
    }

    private async Task CloseAsync()
    {
        result = null;
        newKeyPassphrase = string.Empty;
        if (OnClose.HasDelegate)
            await OnClose.InvokeAsync();
    }
}
