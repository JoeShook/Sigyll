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
using Microsoft.EntityFrameworkCore;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.UI.Services;

namespace Sigyll.UI.Components.Pages;

/// <summary>Issue Direct PQC Pair: an ML-DSA signing and an ML-KEM encryption certificate for one Direct address or domain.</summary>
public partial class CertificateExplorer
{
    [Inject] private DirectPqcPairService DirectPairService { get; set; } = null!;

    private bool directPairDialogHidden = true;
    private int directPairCaId;
    private string directPairCaName = string.Empty;
    private DirectBinding directPairBinding = DirectBinding.Address;
    private string directPairIdentifier = string.Empty;
    private string directPairPassword = string.Empty;
    private List<CertificateTemplate> directSigningTemplates = [];
    private List<CertificateTemplate> directEncryptionTemplates = [];
    private CertificateTemplate? directSigningTemplate;
    private CertificateTemplate? directEncryptionTemplate;
    private bool isIssuingDirectPair;
    private bool isRunningRoundTrip;
    private DirectPairResult? directPairResult;
    private DirectRoundTripResult? directRoundTrip;

    private string DirectPairBindingValue
    {
        get => directPairBinding.ToString();
        set => directPairBinding = Enum.Parse<DirectBinding>(value);
    }

    private async Task ShowDirectPairDialog(int caId, string caName)
    {
        directPairCaId = caId;
        directPairCaName = caName;
        directPairBinding = DirectBinding.Address;
        directPairIdentifier = string.Empty;
        directPairResult = null;
        directRoundTrip = null;
        directPairPassword = PasswordCache.Get(PasswordCacheKey(caId)) ?? string.Empty;

        await using var db = await DbFactory.CreateDbContextAsync();
        var templates = await db.CertificateTemplates.OrderBy(t => t.Name).ToListAsync();
        directSigningTemplates = templates.Where(DirectPqcPairService.IsSigningTemplate).ToList();
        directEncryptionTemplates = templates.Where(DirectPqcPairService.IsEncryptionTemplate).ToList();
        directSigningTemplate = directSigningTemplates.FirstOrDefault(t => t.Name.StartsWith("Direct")) ?? directSigningTemplates.FirstOrDefault();
        directEncryptionTemplate = directEncryptionTemplates.FirstOrDefault(t => t.Name.StartsWith("Direct")) ?? directEncryptionTemplates.FirstOrDefault();

        directPairDialogHidden = false;
    }

    private bool CanIssueDirectPair =>
        !isIssuingDirectPair && directPairResult?.Success != true
        && !string.IsNullOrWhiteSpace(directPairIdentifier) && !string.IsNullOrWhiteSpace(directPairPassword)
        && directSigningTemplate != null && directEncryptionTemplate != null;

    private async Task IssueDirectPairAsync()
    {
        isIssuingDirectPair = true;
        directRoundTrip = null;
        StateHasChanged();
        try
        {
            var baseUrls = (selectedTrustDomain?.BaseUrls ?? new()).Select(bu => bu.Url).ToList();
            var validator = IssuanceService.Validator;
            directPairResult = await DirectPairService.IssuePairAsync(new DirectPairRequest
            {
                TrustDomainId = TrustDomainId,
                IssuingCaCertificateId = directPairCaId,
                Binding = directPairBinding,
                Identifier = directPairIdentifier,
                SigningTemplateId = directSigningTemplate!.Id,
                EncryptionTemplateId = directEncryptionTemplate!.Id,
                PfxPassword = directPairPassword,
                CdpUrls = validator.ExpandCdpTemplates(directSigningTemplate, baseUrls, directPairCaName)
                    .Where(u => !u.Contains("{BaseUrl}", StringComparison.OrdinalIgnoreCase)).ToList(),
                AiaUrls = validator.ExpandAiaTemplates(directSigningTemplate, baseUrls, directPairCaName)
                    .Where(u => !u.Contains("{BaseUrl}", StringComparison.OrdinalIgnoreCase)).ToList(),
            });

            if (directPairResult.Success)
            {
                ToastService.ShowSuccess($"Direct PQC pair issued for {directPairIdentifier.Trim()}");
                await LoadTrustDomainTreeAsync(TrustDomainId);
            }
            else
            {
                ToastService.ShowCopyableError(directPairResult.Error ?? "Pair issuance failed.");
            }
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Pair issuance failed: {ex.Message}");
        }
        finally
        {
            isIssuingDirectPair = false;
            StateHasChanged();
        }
    }

    private async Task RunDirectRoundTripAsync()
    {
        if (directPairResult is not { Success: true }) return;
        isRunningRoundTrip = true;
        directRoundTrip = null;
        StateHasChanged();
        try
        {
            directRoundTrip = await DirectPairService.RunRoundTripAsync(
                directPairResult.SigningCertificateId!.Value, directPairResult.EncryptionCertificateId!.Value);
        }
        catch (Exception ex)
        {
            ToastService.ShowCopyableError($"Round trip failed: {ex.Message}");
        }
        finally
        {
            isRunningRoundTrip = false;
            StateHasChanged();
        }
    }
}
