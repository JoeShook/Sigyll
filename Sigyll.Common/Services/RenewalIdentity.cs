#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Validators;
using Sigyll.Common.ViewModels;

namespace Sigyll.Common.Services;

/// <summary>
/// A renewal or re-key replaces the key and validity of a certificate, not the identity it vouches for: the
/// subject and Subject Alternative Names must be the predecessor's (RFC 3647 §4.6, §4.7). Changing a name is a
/// modification (§4.8), which needs the new name validated like a first issuance, so it is a new certificate.
/// </summary>
public static class RenewalIdentity
{
    /// <summary>
    /// Describes how the requested subject or SANs differ from the predecessor certificate, or returns null when
    /// they are the same. RDN order and the case of DNS names and email addresses are not significant.
    /// </summary>
    public static string? FindChange(X509Certificate2 predecessor, string subjectDn, IEnumerable<SanEntry> subjectAltNames)
    {
        X500DistinguishedName requested;
        try
        {
            requested = new X500DistinguishedName(DistinguishedNameText.Normalize(subjectDn));
        }
        catch (Exception)
        {
            return $"the subject '{subjectDn}' could not be parsed";
        }

        if (!SameNames(Rdns(requested), Rdns(predecessor.SubjectName)))
            return $"the subject changes from '{predecessor.Subject}' to '{requested.Name}'";

        var before = CsrGenerationService.ExtractSubjectAltNames(predecessor).Select(Key).ToHashSet();
        var after = subjectAltNames.Where(s => !string.IsNullOrWhiteSpace(s.Value)).Select(Key).ToHashSet();

        var added = after.Except(before).ToList();
        var removed = before.Except(after).ToList();
        if (added.Count == 0 && removed.Count == 0)
            return null;

        var parts = new List<string>();
        if (added.Count > 0) parts.Add($"adds {string.Join(", ", added)}");
        if (removed.Count > 0) parts.Add($"removes {string.Join(", ", removed)}");
        return $"the SANs change: {string.Join("; ", parts)}";
    }

    /// <summary>
    /// Whether a profile issues the same kind of certificate as <paramref name="predecessor"/>: the same CA flag,
    /// key usages and extended key usages, with every SAN type it requires present in
    /// <paramref name="subjectAltNames"/>. Algorithm, key size and validity may differ; that is what a re-key is for.
    /// </summary>
    public static bool IsCompatibleProfile(CertificateProfile profile, X509Certificate2 predecessor, IEnumerable<SanEntry> subjectAltNames)
    {
        var isCa = predecessor.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority ?? false;
        if (profile.IsBasicConstraintsCa != isCa)
            return false;

        var keyUsage = predecessor.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsage != null && (X509KeyUsageFlags)profile.KeyUsageFlags != keyUsage.KeyUsages)
            return false;

        var ekus = predecessor.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(e => e.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>())
            .Select(o => o.Value ?? string.Empty)
            .ToHashSet();
        var profileEkus = (profile.ExtendedKeyUsageOids ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet();
        if (!ekus.SetEquals(profileEkus))
            return false;

        return IssuanceValidator.FindMissingSanTypes(profile.SubjectAltNameTypes,
            subjectAltNames.Where(s => !string.IsNullOrWhiteSpace(s.Value)).Select(s => s.Type)).Count == 0;
    }

    private static List<(string Oid, string Value)> Rdns(X500DistinguishedName name) =>
        name.EnumerateRelativeDistinguishedNames()
            .Select(r => r.HasMultipleElements
                ? ("multi-valued", Convert.ToHexString(r.RawData.Span))
                : (r.GetSingleElementType().Value ?? string.Empty, r.GetSingleElementValue() ?? string.Empty))
            .ToList();

    private static bool SameNames(List<(string Oid, string Value)> a, List<(string Oid, string Value)> b)
    {
        static IEnumerable<string> Keys(IEnumerable<(string Oid, string Value)> rdns) =>
            rdns.Select(r => $"{r.Oid}={r.Value.Trim().ToUpperInvariant()}").Order(StringComparer.Ordinal);

        return a.Count == b.Count && Keys(a).SequenceEqual(Keys(b));
    }

    private static string Key(SanEntry san)
    {
        var value = san.Value.Trim();
        value = san.Type switch
        {
            SanType.Dns or SanType.Email => value.ToLowerInvariant(),
            SanType.IpAddress when IPAddress.TryParse(value, out var ip) => ip.ToString(),
            _ => value,
        };
        return $"{san.Type}:{value}";
    }
}
