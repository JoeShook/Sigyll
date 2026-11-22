#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Sigyll.Common.Services;

/// <summary>
/// The certificatePolicies extension (RFC 5280 §4.2.1.4, OID 2.5.29.32): the policy OIDs a certificate is issued
/// under. Trust frameworks such as DirectTrust require specific policy OIDs on the certificates they accept.
/// A profile stores its policies as semicolon-delimited OIDs, like its extended key usages; the helpers here
/// parse that text, build the extension from it, and read the policies back from a certificate.
/// </summary>
public static partial class CertificatePolicyExtension
{
    public const string CertificatePoliciesOid = "2.5.29.32";

    /// <summary>The special policy that stands for every policy (RFC 5280 §4.2.1.4).</summary>
    public const string AnyPolicyOid = "2.5.29.32.0";

    private const string CpsQualifierOid = "1.3.6.1.5.5.7.2.1";
    private const string UserNoticeQualifierOid = "1.3.6.1.5.5.7.2.2";

    private static readonly char[] Separators = [';', ',', ' ', '\t', '\r', '\n'];

    /// <summary>
    /// Splits policy text into OIDs. Semicolons, commas, spaces and line breaks all separate entries; blanks
    /// and repeats are dropped and the order is kept.
    /// </summary>
    public static IReadOnlyList<string> Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return [];

        return text.Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// The stored form of policy text: the OIDs joined with semicolons, or null when there are none.
    /// </summary>
    public static string? Normalize(string? text)
    {
        var oids = Parse(text);
        return oids.Count == 0 ? null : string.Join(";", oids);
    }

    /// <summary>The entries in <paramref name="text"/> that are not dotted-decimal OIDs.</summary>
    public static IReadOnlyList<string> FindInvalid(string? text) =>
        Parse(text).Where(oid => !IsValidOid(oid)).ToList();

    /// <summary>
    /// Whether <paramref name="oid"/> is a dotted-decimal object identifier: at least two arcs, the first 0, 1
    /// or 2, the second at most 39 under 0 and 1, and no leading zeros.
    /// </summary>
    public static bool IsValidOid(string? oid)
    {
        if (string.IsNullOrEmpty(oid) || !OidPattern().IsMatch(oid))
            return false;

        var arcs = oid.Split('.');
        return arcs[0] == "2" || (arcs[1].Length <= 2 && int.Parse(arcs[1]) <= 39);
    }

    /// <summary>
    /// Builds the extension listing <paramref name="policyOids"/>, without qualifiers, or returns null when there
    /// are none. RFC 5280 lets the extension be critical or not; it is non-critical unless asked otherwise.
    /// </summary>
    /// <exception cref="ArgumentException">An entry is not a dotted-decimal OID.</exception>
    public static X509Extension? Build(IEnumerable<string> policyOids, bool critical = false)
    {
        var oids = policyOids
            .Select(o => o.Trim())
            .Where(o => o.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (oids.Count == 0)
            return null;

        var invalid = oids.FirstOrDefault(o => !IsValidOid(o));
        if (invalid != null)
            throw new ArgumentException($"'{invalid}' is not a valid certificate policy OID.", nameof(policyOids));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var oid in oids)
            {
                using (writer.PushSequence())
                    writer.WriteObjectIdentifier(oid);
            }
        }

        return new X509Extension(new Oid(CertificatePoliciesOid, "Certificate Policies"), writer.Encode(), critical);
    }

    /// <summary>Builds the extension from policy text in the stored form (see <see cref="Parse"/>).</summary>
    public static X509Extension? Build(string? policyText, bool critical = false) =>
        Build(Parse(policyText), critical);

    /// <summary>The policy OIDs in <paramref name="certificate"/>, or an empty list when it has none.</summary>
    public static IReadOnlyList<string> Read(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions[CertificatePoliciesOid];
        return extension == null ? [] : Decode(extension).Select(p => p.PolicyOid).ToList();
    }

    /// <summary>
    /// Decodes the extension into its policies and their qualifiers (CPS URIs and user notice text).
    /// </summary>
    /// <exception cref="AsnContentException">The extension is not a valid certificatePolicies value.</exception>
    public static IReadOnlyList<CertificatePolicy> Decode(X509Extension extension)
    {
        var policies = new List<CertificatePolicy>();
        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        while (sequence.HasData)
        {
            var info = sequence.ReadSequence();
            var oid = info.ReadObjectIdentifier();
            var qualifiers = new List<string>();

            if (info.HasData)
            {
                var qualifierSequence = info.ReadSequence();
                while (qualifierSequence.HasData)
                {
                    var qualifier = qualifierSequence.ReadSequence();
                    var qualifierId = qualifier.ReadObjectIdentifier();
                    qualifiers.Add(qualifierId switch
                    {
                        CpsQualifierOid => $"CPS: {qualifier.ReadCharacterString(UniversalTagNumber.IA5String)}",
                        UserNoticeQualifierOid => $"User notice: {ReadUserNotice(qualifier)}",
                        _ => $"{qualifierId}: {Convert.ToHexString(qualifier.ReadEncodedValue().Span)}",
                    });
                }
            }

            policies.Add(new CertificatePolicy(oid, qualifiers));
        }

        return policies;
    }

    /// <summary>
    /// Text for the certificate viewer: one line per policy OID, with any qualifiers indented beneath it. Falls
    /// back to the hex of the extension when it cannot be decoded.
    /// </summary>
    public static string Describe(X509Extension extension)
    {
        try
        {
            var text = new StringBuilder();
            foreach (var policy in Decode(extension))
            {
                if (text.Length > 0) text.Append('\n');
                text.Append(policy.PolicyOid);
                if (policy.PolicyOid == AnyPolicyOid) text.Append(" (anyPolicy)");
                foreach (var qualifier in policy.Qualifiers)
                    text.Append("\n    ").Append(qualifier);
            }

            return text.ToString();
        }
        catch (Exception ex) when (ex is AsnContentException or ArgumentException)
        {
            return Convert.ToHexString(extension.RawData);
        }
    }

    private static string ReadUserNotice(AsnReader qualifier)
    {
        // UserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL, explicitText DisplayText OPTIONAL }
        var notice = qualifier.ReadSequence();
        string? explicitText = null;
        while (notice.HasData)
        {
            var tag = notice.PeekTag();
            if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Sequence)
            {
                notice.ReadEncodedValue(); // noticeRef: organization and notice numbers, not shown
                continue;
            }

            explicitText = notice.ReadCharacterString((UniversalTagNumber)tag.TagValue);
        }

        return explicitText ?? "(notice reference only)";
    }

    [GeneratedRegex(@"^[0-2](\.(0|[1-9][0-9]*))+$")]
    private static partial Regex OidPattern();
}

/// <summary>One entry of a certificatePolicies extension: the policy OID and its qualifiers as display text.</summary>
public sealed record CertificatePolicy(string PolicyOid, IReadOnlyList<string> Qualifiers);
