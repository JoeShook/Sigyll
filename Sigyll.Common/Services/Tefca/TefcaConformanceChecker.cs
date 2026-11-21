#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Sigyll.Common.Services.Tefca;

/// <summary>The outcome of one conformance check.</summary>
public enum ConformanceOutcome
{
    Pass,
    Fail,

    /// <summary>Not a failure: the requirement is unsettled or advisory.</summary>
    Warning,

    /// <summary>The check did not run (it does not apply, or it was not asked for).</summary>
    Skipped,
}

/// <summary>One named check and what it found.</summary>
public sealed record ConformanceCheckResult(string Name, ConformanceOutcome Outcome, string Detail)
{
    public static ConformanceCheckResult Pass(string name, string detail) => new(name, ConformanceOutcome.Pass, detail);
    public static ConformanceCheckResult Fail(string name, string detail) => new(name, ConformanceOutcome.Fail, detail);
    public static ConformanceCheckResult Warning(string name, string detail) => new(name, ConformanceOutcome.Warning, detail);
    public static ConformanceCheckResult Skipped(string name, string detail) => new(name, ConformanceOutcome.Skipped, detail);
}

/// <summary>The TEFCA environment a certificate is issued for, which sets its OU and whether policies are required.</summary>
public enum TefcaEnvironment
{
    /// <summary>OU=RCE-FHIR; the DirectTrust policy OIDs are required.</summary>
    Production,

    /// <summary>OU=RCE-FHIR-TEST.</summary>
    Validation,
}

/// <summary>
/// Checks whether a URL answers. Injected so the conformance check can confirm CDP/AIA reachability online, and so
/// unit tests never touch the network.
/// </summary>
public interface IUrlReachabilityProbe
{
    /// <summary>Returns null when <paramref name="url"/> answers successfully, otherwise why it did not.</summary>
    Task<string?> ProbeAsync(Uri url, CancellationToken cancellationToken = default);
}

/// <summary>
/// The rule for the exchange purpose carried in a TEFCA client certificate's SAN URI. The SAN form is not settled,
/// so the rule is replaceable; its result should be a warning, never a failure, until the form is published.
/// </summary>
public interface ITefcaSanFormatRule
{
    ConformanceCheckResult Evaluate(IReadOnlyList<string> sanUris);
}

/// <summary>
/// Accepts a SAN URI carrying an authorized exchange purpose code in any candidate form: a fragment
/// (<c>#T-TRTMNT</c>), the last path segment (<c>/T-TRTMNT</c>) or an <c>xp</c> query parameter
/// (<c>?xp=T-TRTMNT</c>). Anything else is a warning.
/// </summary>
public sealed class TefcaSanFormatRule : ITefcaSanFormatRule
{
    public const string CheckName = "SAN exchange purpose format";

    public static TefcaSanFormatRule Default { get; } = new();

    public ConformanceCheckResult Evaluate(IReadOnlyList<string> sanUris)
    {
        foreach (var uri in sanUris)
        {
            if (TefcaExchangePurpose.TryFromSanUri(uri, out var code, out var form))
                return ConformanceCheckResult.Pass(CheckName,
                    $"'{uri}' carries exchange purpose {code} as a {Describe(form)}. The TEFCA client SAN form is not settled.");
        }

        return ConformanceCheckResult.Warning(CheckName, sanUris.Count == 0
            ? "No SAN URI carries an exchange purpose code. The TEFCA client SAN form is not settled; a fragment, path segment or xp query are accepted."
            : $"None of the SAN URIs ({string.Join(", ", sanUris)}) carries an authorized exchange purpose code as a fragment, path segment or xp query. The TEFCA client SAN form is not settled.");
    }

    private static string Describe(TefcaExchangePurpose.SanForm form) => form switch
    {
        TefcaExchangePurpose.SanForm.Fragment => "fragment",
        TefcaExchangePurpose.SanForm.PathSegment => "path segment",
        _ => "xp query parameter",
    };
}

/// <summary>Settings for <see cref="TefcaConformanceChecker"/>.</summary>
public sealed class TefcaConformanceOptions
{
    /// <summary>
    /// The environment to check against. Null infers it from the subject OU (RCE-FHIR or RCE-FHIR-TEST); when the OU
    /// names neither, the production rules apply.
    /// </summary>
    public TefcaEnvironment? Environment { get; init; }

    /// <summary>The rule for the exchange purpose in the SAN URI.</summary>
    public ITefcaSanFormatRule SanFormatRule { get; init; } = TefcaSanFormatRule.Default;

    /// <summary>When set, every CDP and AIA URL is probed; otherwise the reachability check is skipped.</summary>
    public IUrlReachabilityProbe? ReachabilityProbe { get; init; }
}

/// <summary>
/// Checks an end-entity certificate against the TEFCA FHIR certificate profile and returns one named result per
/// requirement: the subject OU, a root → intermediate → leaf chain, keyUsage and basicConstraints, SANs and CN,
/// the DirectTrust certificate policies (production), http CDP/AIA (and optionally their reachability), the key,
/// signature algorithm and validity period, and the SAN exchange purpose form (a warning only).
/// </summary>
public static class TefcaConformanceChecker
{
    public const string ProductionOu = "RCE-FHIR";
    public const string ValidationOu = "RCE-FHIR-TEST";

    /// <summary>DirectTrust certificate policy OIDs a production TEFCA FHIR certificate must carry.</summary>
    public static readonly IReadOnlyList<string> ProductionPolicyOids =
    [
        "1.3.6.1.4.1.41179.0.2",
        "1.3.6.1.4.1.41179.1.5",
        "1.3.6.1.4.1.41179.3.1",
    ];

    public const int MaxCommonNameLength = 64;
    public const int MinRsaKeySize = 2048;
    public const int MaxValidityYears = 3;

    private const string Sha256WithRsaOid = "1.2.840.113549.1.1.11";
    private const string SanOid = "2.5.29.17";
    private const string CdpOid = "2.5.29.31";
    private const string AiaOid = "1.3.6.1.5.5.7.1.1";
    private const string CaIssuersOid = "1.3.6.1.5.5.7.48.2";

    /// <summary>
    /// Runs every check. <paramref name="issuers"/> is the issuing chain, nearest first (intermediate, then root).
    /// Reachability is probed only when <see cref="TefcaConformanceOptions.ReachabilityProbe"/> is set.
    /// </summary>
    public static async Task<IReadOnlyList<ConformanceCheckResult>> CheckAsync(
        X509Certificate2 leaf, IReadOnlyList<X509Certificate2> issuers, TefcaConformanceOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(leaf);
        ArgumentNullException.ThrowIfNull(issuers);
        options ??= new TefcaConformanceOptions();

        var ous = ReadOrganizationalUnits(leaf);
        var environment = options.Environment ?? InferEnvironment(ous) ?? TefcaEnvironment.Production;
        var sanUris = ReadSanUris(leaf, out var dnsNames);
        var cdpUrls = ReadCdpUrls(leaf);
        var aiaUrls = ReadAiaUrls(leaf);

        var results = new List<ConformanceCheckResult>
        {
            CheckOu(ous, options.Environment),
            CheckChain(leaf, issuers),
            CheckKeyUsage(leaf),
            CheckBasicConstraints(leaf),
            CheckNoDnsNames(dnsNames),
            CheckCommonName(leaf, sanUris),
            CheckPolicies(leaf, environment),
            CheckHttpUrls("CRL distribution point", cdpUrls),
            CheckHttpUrls("AIA caIssuers", aiaUrls),
            await CheckReachabilityAsync(cdpUrls.Concat(aiaUrls).ToList(), options.ReachabilityProbe, cancellationToken),
            CheckKey(leaf),
            CheckSignatureAlgorithm(leaf),
            CheckValidity(leaf),
            options.SanFormatRule.Evaluate(sanUris),
        };

        return results;
    }

    /// <summary>The environment named by the subject OU, or null when it names neither.</summary>
    public static TefcaEnvironment? InferEnvironment(IReadOnlyList<string> organizationalUnits) =>
        organizationalUnits.Contains(ProductionOu, StringComparer.Ordinal) ? TefcaEnvironment.Production
        : organizationalUnits.Contains(ValidationOu, StringComparer.Ordinal) ? TefcaEnvironment.Validation
        : null;

    /// <summary>Whether any result failed (warnings and skipped checks do not count).</summary>
    public static bool HasFailures(IEnumerable<ConformanceCheckResult> results) =>
        results.Any(r => r.Outcome == ConformanceOutcome.Fail);

    private static ConformanceCheckResult CheckOu(IReadOnlyList<string> ous, TefcaEnvironment? expected)
    {
        const string name = "Subject OU";
        var shown = ous.Count == 0 ? "none" : string.Join(", ", ous);

        if (expected is TefcaEnvironment env)
        {
            var want = env == TefcaEnvironment.Production ? ProductionOu : ValidationOu;
            return ous.Contains(want, StringComparer.Ordinal)
                ? ConformanceCheckResult.Pass(name, $"OU={want} ({env.ToString().ToLowerInvariant()}).")
                : ConformanceCheckResult.Fail(name, $"Expected OU={want} for {env.ToString().ToLowerInvariant()}; found {shown}.");
        }

        return InferEnvironment(ous) switch
        {
            TefcaEnvironment.Production => ConformanceCheckResult.Pass(name, $"OU={ProductionOu} (production)."),
            TefcaEnvironment.Validation => ConformanceCheckResult.Pass(name, $"OU={ValidationOu} (validation)."),
            _ => ConformanceCheckResult.Fail(name,
                $"Expected OU={ProductionOu} (production) or OU={ValidationOu} (validation); found {shown}."),
        };
    }

    private static ConformanceCheckResult CheckChain(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> issuers)
    {
        const string name = "Chain root → intermediate → leaf";
        if (issuers.Count != 2)
            return ConformanceCheckResult.Fail(name,
                $"Expected exactly one intermediate and a root above the leaf (3 certificates); found {issuers.Count + 1}.");

        var intermediate = issuers[0];
        var root = issuers[1];

        if (!IsCa(intermediate))
            return ConformanceCheckResult.Fail(name, $"The issuer '{intermediate.Subject}' is not a CA.");
        if (!IsCa(root))
            return ConformanceCheckResult.Fail(name, $"The root '{root.Subject}' is not a CA.");
        if (!root.SubjectName.RawData.AsSpan().SequenceEqual(root.IssuerName.RawData))
            return ConformanceCheckResult.Fail(name, $"The top certificate '{root.Subject}' is not self-signed, so it is not a root.");
        if (intermediate.SubjectName.RawData.AsSpan().SequenceEqual(intermediate.IssuerName.RawData))
            return ConformanceCheckResult.Fail(name, $"The issuer '{intermediate.Subject}' is self-signed; the leaf must be issued by an intermediate.");

        var leafError = CertificateIssuanceService.VerifyIssuedBy(leaf, intermediate);
        if (leafError != null)
            return ConformanceCheckResult.Fail(name, $"Leaf → intermediate: {leafError}");
        var intermediateError = CertificateIssuanceService.VerifyIssuedBy(intermediate, root);
        if (intermediateError != null)
            return ConformanceCheckResult.Fail(name, $"Intermediate → root: {intermediateError}");

        return ConformanceCheckResult.Pass(name, $"{root.GetNameInfo(X509NameType.SimpleName, false)} → "
            + $"{intermediate.GetNameInfo(X509NameType.SimpleName, false)} → {leaf.GetNameInfo(X509NameType.SimpleName, false)}.");
    }

    private static ConformanceCheckResult CheckKeyUsage(X509Certificate2 leaf)
    {
        const string name = "keyUsage digitalSignature only, critical";
        if (leaf.Extensions["2.5.29.15"] is not X509KeyUsageExtension ku)
            return ConformanceCheckResult.Fail(name, "The keyUsage extension is missing.");

        var problems = new List<string>();
        if (ku.KeyUsages != X509KeyUsageFlags.DigitalSignature)
            problems.Add($"key usages are {ku.KeyUsages}");
        if (!ku.Critical)
            problems.Add("the extension is not critical");

        return problems.Count == 0
            ? ConformanceCheckResult.Pass(name, "digitalSignature, critical.")
            : ConformanceCheckResult.Fail(name, $"Expected only digitalSignature, critical; {string.Join(" and ", problems)}.");
    }

    private static ConformanceCheckResult CheckBasicConstraints(X509Certificate2 leaf)
    {
        const string name = "basicConstraints cA=false, critical";
        if (leaf.Extensions["2.5.29.19"] is not X509BasicConstraintsExtension bc)
            return ConformanceCheckResult.Fail(name, "The basicConstraints extension is missing.");

        var problems = new List<string>();
        if (bc.CertificateAuthority)
            problems.Add("cA is true");
        if (!bc.Critical)
            problems.Add("the extension is not critical");

        return problems.Count == 0
            ? ConformanceCheckResult.Pass(name, "cA=false, critical.")
            : ConformanceCheckResult.Fail(name, $"Expected cA=false, critical; {string.Join(" and ", problems)}.");
    }

    private static ConformanceCheckResult CheckNoDnsNames(IReadOnlyList<string> dnsNames)
    {
        const string name = "No dNSName SANs";
        return dnsNames.Count == 0
            ? ConformanceCheckResult.Pass(name, "The certificate has no dNSName SANs.")
            : ConformanceCheckResult.Fail(name, $"dNSName SANs are not allowed; found {string.Join(", ", dnsNames)}.");
    }

    private static ConformanceCheckResult CheckCommonName(X509Certificate2 leaf, IReadOnlyList<string> sanUris)
    {
        const string name = "CN ≤ 64 characters and equal to a SAN URI";
        var cn = ReadAttribute(leaf, "2.5.4.3").FirstOrDefault();
        if (string.IsNullOrEmpty(cn))
            return ConformanceCheckResult.Fail(name, "The subject has no CN.");

        var problems = new List<string>();
        if (cn.Length > MaxCommonNameLength)
            problems.Add($"the CN is {cn.Length} characters");
        if (!sanUris.Contains(cn, StringComparer.Ordinal))
            problems.Add(sanUris.Count == 0 ? "there are no SAN URIs" : "no SAN URI equals the CN");

        return problems.Count == 0
            ? ConformanceCheckResult.Pass(name, $"CN '{cn}' ({cn.Length} characters) matches a SAN URI.")
            : ConformanceCheckResult.Fail(name, $"CN '{cn}': {string.Join(" and ", problems)}.");
    }

    private static ConformanceCheckResult CheckPolicies(X509Certificate2 leaf, TefcaEnvironment environment)
    {
        const string name = "DirectTrust certificate policies";
        IReadOnlyList<string> present;
        try
        {
            present = CertificatePolicyExtension.Read(leaf);
        }
        catch (System.Formats.Asn1.AsnContentException ex)
        {
            return ConformanceCheckResult.Fail(name, $"The certificatePolicies extension cannot be read: {ex.Message}");
        }

        if (environment != TefcaEnvironment.Production)
            return ConformanceCheckResult.Skipped(name, "Required for production certificates only.");

        var missing = ProductionPolicyOids.Where(oid => !present.Contains(oid, StringComparer.Ordinal)).ToList();
        return missing.Count == 0
            ? ConformanceCheckResult.Pass(name, $"Carries {string.Join(", ", ProductionPolicyOids)}.")
            : ConformanceCheckResult.Fail(name, $"Missing {string.Join(", ", missing)}.");
    }

    private static ConformanceCheckResult CheckHttpUrls(string what, IReadOnlyList<string> urls)
    {
        var name = $"{what} uses http";
        if (urls.Count == 0)
            return ConformanceCheckResult.Fail(name, $"The certificate has no {what} URL.");

        var notHttp = urls.Where(u => !u.StartsWith("http://", StringComparison.OrdinalIgnoreCase)).ToList();
        return notHttp.Count == 0
            ? ConformanceCheckResult.Pass(name, string.Join(", ", urls))
            : ConformanceCheckResult.Fail(name, $"Not plain http: {string.Join(", ", notHttp)}.");
    }

    private static async Task<ConformanceCheckResult> CheckReachabilityAsync(
        IReadOnlyList<string> urls, IUrlReachabilityProbe? probe, CancellationToken cancellationToken)
    {
        const string name = "CDP/AIA reachable";
        if (probe == null)
            return ConformanceCheckResult.Skipped(name, "Not checked; run the check online to probe the URLs.");
        if (urls.Count == 0)
            return ConformanceCheckResult.Skipped(name, "There are no CDP or AIA URLs to probe.");

        var failures = new List<string>();
        foreach (var url in urls.Distinct(StringComparer.Ordinal))
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                failures.Add($"{url}: not an absolute URL");
                continue;
            }

            var error = await probe.ProbeAsync(uri, cancellationToken);
            if (error != null)
                failures.Add($"{url}: {error}");
        }

        return failures.Count == 0
            ? ConformanceCheckResult.Pass(name, $"All {urls.Distinct(StringComparer.Ordinal).Count()} URL(s) answered.")
            : ConformanceCheckResult.Fail(name, string.Join("; ", failures));
    }

    private static ConformanceCheckResult CheckKey(X509Certificate2 leaf)
    {
        const string name = "RSA key ≥ 2048 bits";
        using var rsa = leaf.GetRSAPublicKey();
        if (rsa == null)
            return ConformanceCheckResult.Fail(name, $"The key is not RSA ({leaf.PublicKey.Oid.FriendlyName ?? leaf.PublicKey.Oid.Value}).");

        return rsa.KeySize >= MinRsaKeySize
            ? ConformanceCheckResult.Pass(name, $"RSA {rsa.KeySize}.")
            : ConformanceCheckResult.Fail(name, $"RSA {rsa.KeySize} is shorter than {MinRsaKeySize} bits.");
    }

    private static ConformanceCheckResult CheckSignatureAlgorithm(X509Certificate2 leaf)
    {
        const string name = "Signature SHA-256 with RSA";
        return leaf.SignatureAlgorithm.Value == Sha256WithRsaOid
            ? ConformanceCheckResult.Pass(name, "sha256WithRSAEncryption.")
            : ConformanceCheckResult.Fail(name,
                $"Signed with {leaf.SignatureAlgorithm.FriendlyName ?? leaf.SignatureAlgorithm.Value}; expected sha256WithRSAEncryption.");
    }

    private static ConformanceCheckResult CheckValidity(X509Certificate2 leaf)
    {
        const string name = "Validity ≤ 3 years";
        var notBefore = leaf.NotBefore.ToUniversalTime();
        var notAfter = leaf.NotAfter.ToUniversalTime();
        var days = (notAfter - notBefore).TotalDays;

        return notAfter <= notBefore.AddYears(MaxValidityYears)
            ? ConformanceCheckResult.Pass(name, $"{days:0} days.")
            : ConformanceCheckResult.Fail(name, $"{days:0} days is longer than {MaxValidityYears} years.");
    }

    private static bool IsCa(X509Certificate2 cert) =>
        cert.Extensions["2.5.29.19"] is X509BasicConstraintsExtension { CertificateAuthority: true };

    internal static IReadOnlyList<string> ReadOrganizationalUnits(X509Certificate2 cert) => ReadAttribute(cert, "2.5.4.11");

    private static IReadOnlyList<string> ReadAttribute(X509Certificate2 cert, string attributeOid)
    {
        var values = new List<string>();
        foreach (var rdn in cert.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (!rdn.HasMultipleElements && rdn.GetSingleElementType().Value == attributeOid
                && rdn.GetSingleElementValue() is { } value)
                values.Add(value);
        }

        return values;
    }

    internal static IReadOnlyList<string> ReadSanUris(X509Certificate2 cert, out IReadOnlyList<string> dnsNames)
    {
        var uris = new List<string>();
        var dns = new List<string>();
        dnsNames = dns;

        var ext = cert.Extensions[SanOid];
        if (ext == null)
            return uris;

        foreach (var gn in GeneralNames.GetInstance(Asn1Object.FromByteArray(ext.RawData)).GetNames())
        {
            if (gn.TagNo == GeneralName.UniformResourceIdentifier)
                uris.Add(gn.Name.ToString()!);
            else if (gn.TagNo == GeneralName.DnsName)
                dns.Add(gn.Name.ToString()!);
        }

        return uris;
    }

    internal static IReadOnlyList<string> ReadCdpUrls(X509Certificate2 cert)
    {
        var urls = new List<string>();
        var ext = cert.Extensions[CdpOid];
        if (ext == null)
            return urls;

        foreach (var dp in CrlDistPoint.GetInstance(Asn1Object.FromByteArray(ext.RawData)).GetDistributionPoints())
        {
            if (dp.DistributionPointName?.Type != DistributionPointName.FullName)
                continue;
            foreach (var gn in GeneralNames.GetInstance(dp.DistributionPointName.Name).GetNames())
            {
                if (gn.TagNo == GeneralName.UniformResourceIdentifier)
                    urls.Add(gn.Name.ToString()!);
            }
        }

        return urls;
    }

    internal static IReadOnlyList<string> ReadAiaUrls(X509Certificate2 cert)
    {
        var urls = new List<string>();
        var ext = cert.Extensions[AiaOid];
        if (ext == null)
            return urls;

        foreach (var ad in AuthorityInformationAccess.GetInstance(Asn1Object.FromByteArray(ext.RawData)).GetAccessDescriptions())
        {
            if (ad.AccessMethod.Id == CaIssuersOid && ad.AccessLocation.TagNo == GeneralName.UniformResourceIdentifier)
                urls.Add(ad.AccessLocation.Name.ToString()!);
        }

        return urls;
    }
}
