#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Data.Entities;
using Sigyll.Common.ViewModels;

namespace Sigyll.Common.Validators;

public class IssuanceWarning
{
    public string Category { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public class IssuanceValidator
{
    public HashSet<int> FindSupersededCaIds(List<CaCertificate> allCas)
    {
        var superseded = new HashSet<int>();

        var groups = allCas
            .Where(ca => !ca.IsArchived && !ca.IsRevoked)
            .GroupBy(ca => ca.Subject, StringComparer.OrdinalIgnoreCase);

        foreach (var group in groups)
        {
            var sorted = group.OrderByDescending(ca => ca.NotBefore).ToList();
            if (sorted.Count <= 1) continue;

            for (var i = 1; i < sorted.Count; i++)
                superseded.Add(sorted[i].Id);
        }

        return superseded;
    }

    /// <summary>
    /// Parses a profile's semicolon-delimited SubjectAltNameTypes ("URI;DNS;Email;IP")
    /// into SanType values. Unknown tokens are ignored.
    /// </summary>
    public static List<SanType> ParseSanTypes(string? subjectAltNameTypes) =>
        (subjectAltNameTypes ?? string.Empty)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(t => t.ToUpperInvariant() switch
            {
                "URI" => (SanType?)SanType.Uri,
                "DNS" => SanType.Dns,
                "EMAIL" => SanType.Email,
                "IP" => SanType.IpAddress,
                _ => null
            })
            .Where(t => t != null)
            .Select(t => t!.Value)
            .Distinct()
            .ToList();

    /// <summary>
    /// A SAN type declared on a profile is a requirement: every declared type must have at
    /// least one non-empty SAN entry in the request. Returns an error message naming the
    /// missing types, or null when the request satisfies the profile.
    /// </summary>
    public string? ValidateRequiredSanTypes(CertificateProfile profile, IEnumerable<SanEntry> subjectAltNames)
    {
        var missing = FindMissingSanTypes(profile.SubjectAltNameTypes,
            subjectAltNames.Where(s => !string.IsNullOrWhiteSpace(s.Value)).Select(s => s.Type));

        if (missing.Count == 0) return null;

        var names = string.Join(", ", missing.Select(SanTypeDisplayName));
        return $"Profile '{profile.Name}' requires a Subject Alternative Name of type: {names}.";
    }

    /// <summary>
    /// Returns the profile-declared SAN types that have no entry among the provided types.
    /// </summary>
    public static List<SanType> FindMissingSanTypes(string? subjectAltNameTypes, IEnumerable<SanType> providedTypes)
    {
        var provided = new HashSet<SanType>(providedTypes);
        return ParseSanTypes(subjectAltNameTypes).Where(t => !provided.Contains(t)).ToList();
    }

    /// <summary>
    /// Validates individual SAN values. A DNS SAN (dNSName, RFC 5280) must be a bare host
    /// name — no port, scheme, or path; ports are fine in URI SANs. Wildcard prefixes
    /// ("*.example.com") are allowed. Returns an error for the first invalid entry, or null.
    /// </summary>
    public string? ValidateSanValues(IEnumerable<SanEntry> subjectAltNames)
    {
        foreach (var san in subjectAltNames.Where(s => s.Type == SanType.Dns))
        {
            var host = san.Value.Trim();

            if (host.Contains(':'))
                return $"DNS SAN '{san.Value}' must be a bare host name — no port or scheme. " +
                       "Use a URI SAN to carry a port.";

            var checkTarget = host.StartsWith("*.") ? host[2..] : host;
            var hostNameType = Uri.CheckHostName(checkTarget);

            if (hostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
                return $"DNS SAN '{san.Value}' is an IP address. Use the IP SAN type instead.";

            if (hostNameType != UriHostNameType.Dns)
                return $"DNS SAN '{san.Value}' is not a valid DNS host name.";
        }

        return null;
    }

    public static string SanTypeDisplayName(SanType type) => type switch
    {
        SanType.Uri => "URI",
        SanType.Dns => "DNS",
        SanType.Email => "Email",
        SanType.IpAddress => "IP",
        _ => type.ToString()
    };

    public List<IssuanceWarning> CompareTemplateUrls(
        List<string> originalCdpUrls,
        List<string> originalAiaUrls,
        List<string> profileCdpUrls,
        List<string> profileAiaUrls)
    {
        var warnings = new List<IssuanceWarning>();
        var comparer = StringComparer.OrdinalIgnoreCase;

        // Compare in the encoded form written into certificates, so "a b.crl" from the profile
        // matches "a%20b.crl" read from the existing certificate.
        static IEnumerable<string> Encoded(IEnumerable<string> urls) =>
            urls.Select(Sigyll.Common.Services.CertificateExtensionHelpers.EncodeUrl);
        var oldCdp = new HashSet<string>(Encoded(originalCdpUrls), comparer);
        var oldAia = new HashSet<string>(Encoded(originalAiaUrls), comparer);
        var newCdp = new HashSet<string>(Encoded(profileCdpUrls), comparer);
        var newAia = new HashSet<string>(Encoded(profileAiaUrls), comparer);

        foreach (var url in oldCdp.Where(u => !newCdp.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "CDP", Message = $"CDP removed: {url}" });
        foreach (var url in newCdp.Where(u => !oldCdp.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "CDP", Message = $"CDP added: {url}" });
        foreach (var url in oldAia.Where(u => !newAia.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "AIA", Message = $"AIA removed: {url}" });
        foreach (var url in newAia.Where(u => !oldAia.Contains(u)))
            warnings.Add(new IssuanceWarning { Category = "AIA", Message = $"AIA added: {url}" });

        return warnings;
    }

    public List<string> ExpandUrlTemplates(
        CertificateProfile profile,
        List<string> trustDomainBaseUrls,
        string? issuingCaName)
    {
        var cdpTemplate = profile.CdpUrlTemplate;
        if (profile.IncludeCdp && string.IsNullOrWhiteSpace(cdpTemplate))
            cdpTemplate = "{BaseUrl}/crls/{CAName}.crl";

        var aiaTemplate = profile.AiaUrlTemplate;
        if (profile.IncludeAia && string.IsNullOrWhiteSpace(aiaTemplate))
            aiaTemplate = "{BaseUrl}/certs/{CAName}.cer";

        var result = new List<string>();
        result.AddRange(ExpandTemplate(cdpTemplate, trustDomainBaseUrls, issuingCaName));
        result.AddRange(ExpandTemplate(aiaTemplate, trustDomainBaseUrls, issuingCaName));
        return result;
    }

    public List<string> ExpandCdpTemplates(
        CertificateProfile profile,
        List<string> trustDomainBaseUrls,
        string? issuingCaName)
    {
        if (!profile.IncludeCdp) return new();

        var cdpTemplate = profile.CdpUrlTemplate;
        if (string.IsNullOrWhiteSpace(cdpTemplate))
            cdpTemplate = "{BaseUrl}/crls/{CAName}.crl";

        return ExpandTemplate(cdpTemplate, trustDomainBaseUrls, issuingCaName);
    }

    public List<string> ExpandAiaTemplates(
        CertificateProfile profile,
        List<string> trustDomainBaseUrls,
        string? issuingCaName)
    {
        if (!profile.IncludeAia) return new();

        var aiaTemplate = profile.AiaUrlTemplate;
        if (string.IsNullOrWhiteSpace(aiaTemplate))
            aiaTemplate = "{BaseUrl}/certs/{CAName}.cer";

        return ExpandTemplate(aiaTemplate, trustDomainBaseUrls, issuingCaName);
    }

    private static List<string> ExpandTemplate(
        string? profile,
        List<string> baseUrls,
        string? caName)
    {
        if (string.IsNullOrWhiteSpace(profile)) return new();

        if (baseUrls.Count == 0)
        {
            var result = profile;
            if (caName != null)
                result = result.Replace("{CAName}", caName, StringComparison.OrdinalIgnoreCase);
            return string.IsNullOrWhiteSpace(result) ? new() : new() { result };
        }

        var expanded = new List<string>();
        foreach (var baseUrl in baseUrls)
        {
            var result = profile
                .Replace("{BaseUrl}", baseUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)
                .Replace("{CAName}", caName ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            expanded.Add(result);
        }

        return expanded;
    }
}
