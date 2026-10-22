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
using Sigyll.Common.Data;
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
    private List<CertificateProfile> directSigningProfiles = [];
    private List<CertificateProfile> directEncryptionProfiles = [];
    private CertificateProfile? directSigningProfile;
    private CertificateProfile? directEncryptionProfile;
    private bool isIssuingDirectPair;
    private bool isRunningRoundTrip;
    private DirectPairResult? directPairResult;
    private DirectRoundTripResult? directRoundTrip;

    // Re-key mode: the existing pair being replaced and the versioned names the new halves get.
    private DirectPairInfo? directPairRekey;
    private string? directPairSigningName;
    private string? directPairEncryptionName;
    private (List<string> Cdp, List<string> Aia) directPairOldSigningUrls = ([], []);
    private (List<string> Cdp, List<string> Aia) directPairOldEncryptionUrls = ([], []);

    /// <summary>CDP and AIA URLs both new certificates get: the signing profile's templates over the trust domain's base URLs.</summary>
    private (List<string> Cdp, List<string> Aia) DirectPairUrls()
    {
        if (directSigningProfile == null) return ([], []);
        var baseUrls = (selectedTrustDomain?.BaseUrls ?? new()).Select(bu => bu.Url).ToList();
        var validator = IssuanceService.Validator;
        return (validator.ExpandCdpTemplates(directSigningProfile, baseUrls, directPairCaName)
                    .Where(u => !u.Contains("{BaseUrl}", StringComparison.OrdinalIgnoreCase)).ToList(),
                validator.ExpandAiaTemplates(directSigningProfile, baseUrls, directPairCaName)
                    .Where(u => !u.Contains("{BaseUrl}", StringComparison.OrdinalIgnoreCase)).ToList());
    }

    /// <summary>
    /// Re-key mode: how the new pair's CDP/AIA URLs differ from the pair being replaced, as in the
    /// single-certificate re-key. Halves with the same differences are reported once.
    /// </summary>
    private List<string> DirectPairUrlWarnings
    {
        get
        {
            if (directPairRekey == null) return [];
            var (cdp, aia) = DirectPairUrls();
            var validator = IssuanceService.Validator;
            var signing = validator.CompareTemplateUrls(directPairOldSigningUrls.Cdp, directPairOldSigningUrls.Aia, cdp, aia)
                .Select(w => w.Message).ToList();
            var encryption = validator.CompareTemplateUrls(directPairOldEncryptionUrls.Cdp, directPairOldEncryptionUrls.Aia, cdp, aia)
                .Select(w => w.Message).ToList();
            return signing.SequenceEqual(encryption)
                ? signing
                : [.. signing.Select(m => $"Signing: {m}"), .. encryption.Select(m => $"Encryption: {m}")];
        }
    }

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
        directPairRekey = null;
        directPairPassword = PasswordCache.Get(PasswordCacheKey(caId)) ?? string.Empty;

        await using var db = await DbFactory.CreateDbContextAsync();
        var profiles = await db.CertificateProfiles.OrderBy(t => t.Name).ToListAsync();
        directSigningProfiles = profiles.Where(DirectPqcPairService.IsSigningProfile).ToList();
        directEncryptionProfiles = profiles.Where(DirectPqcPairService.IsEncryptionProfile).ToList();
        directSigningProfile = directSigningProfiles.FirstOrDefault(t => t.Name.StartsWith("Direct")) ?? directSigningProfiles.FirstOrDefault();
        directEncryptionProfile = directEncryptionProfiles.FirstOrDefault(t => t.Name.StartsWith("Direct")) ?? directEncryptionProfiles.FirstOrDefault();

        directPairDialogHidden = false;
    }

    /// <summary>
    /// Re-key on either half of a Direct pair re-keys both: the encryption certificate's RFC 9763
    /// link is a hash of the signing certificate, so replacing one half alone would leave the pair
    /// unlinked. Opens the pair dialog with the identity, profiles and versioned names prepared.
    /// </summary>
    private async Task ShowDirectPairRekeyDialogAsync(DirectPairInfo pair)
    {
        await ShowDirectPairDialog(pair.IssuingCaCertificateId, pair.IssuingCaName);
        directPairRekey = pair;
        directPairBinding = pair.Binding;
        directPairIdentifier = pair.Identifier;
        directSigningProfile = directSigningProfiles.FirstOrDefault(t => t.Id == pair.SigningProfileId) ?? directSigningProfile;
        directEncryptionProfile = directEncryptionProfiles.FirstOrDefault(t => t.Id == pair.EncryptionProfileId) ?? directEncryptionProfile;

        await using var db = await DbFactory.CreateDbContextAsync();
        directPairSigningName = await NextRenewalNameAsync(db, pair.SigningName, pair.SigningVersion);
        directPairEncryptionName = await NextRenewalNameAsync(db, pair.EncryptionName, pair.EncryptionVersion);
        directPairOldSigningUrls = await IssuedCertificateUrlsAsync(db, pair.SigningCertificateId);
        directPairOldEncryptionUrls = await IssuedCertificateUrlsAsync(db, pair.EncryptionCertificateId);
    }

    private static async Task<(List<string> Cdp, List<string> Aia)> IssuedCertificateUrlsAsync(SigyllDbContext db, int id)
    {
        var pem = await db.IssuedCertificates.Where(i => i.Id == id).Select(i => i.X509CertificatePem).FirstOrDefaultAsync();
        if (pem == null) return ([], []);
        using var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(pem);
        return (ExtractExtensionUrls(cert, "2.5.29.31"), ExtractExtensionUrls(cert, "1.3.6.1.5.5.7.1.1"));
    }

    private bool CanIssueDirectPair =>
        !isIssuingDirectPair && directPairResult?.Success != true
        && !string.IsNullOrWhiteSpace(directPairIdentifier) && !string.IsNullOrWhiteSpace(directPairPassword)
        && directSigningProfile != null && directEncryptionProfile != null;

    private async Task IssueDirectPairAsync()
    {
        isIssuingDirectPair = true;
        directRoundTrip = null;
        StateHasChanged();
        try
        {
            var (cdpUrls, aiaUrls) = DirectPairUrls();
            directPairResult = await DirectPairService.IssuePairAsync(new DirectPairRequest
            {
                TrustDomainId = TrustDomainId,
                IssuingCaCertificateId = directPairCaId,
                Binding = directPairBinding,
                Identifier = directPairIdentifier,
                SigningProfileId = directSigningProfile!.Id,
                EncryptionProfileId = directEncryptionProfile!.Id,
                PfxPassword = directPairPassword,
                CdpUrls = cdpUrls,
                AiaUrls = aiaUrls,
                RenewalOfSigningId = directPairRekey?.SigningCertificateId,
                RenewalOfEncryptionId = directPairRekey?.EncryptionCertificateId,
                SigningName = directPairRekey != null ? directPairSigningName : null,
                EncryptionName = directPairRekey != null ? directPairEncryptionName : null,
            });

            if (directPairResult.Success)
            {
                ToastService.ShowSuccess(
                    $"Direct PQC pair {(directPairRekey != null ? "re-keyed" : "issued")} for {directPairIdentifier.Trim()}");
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
