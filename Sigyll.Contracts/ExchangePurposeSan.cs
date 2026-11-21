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
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Sigyll.Contracts;

/// <summary>
/// Reads the TEFCA exchange purpose (XP) code a SAN URI carries. The client SAN format is not settled, so this is the
/// one place that knows it: <see cref="Extract"/> accepts the code as the URI fragment
/// (<c>urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT</c>), as the last path segment
/// (<c>https://example.org/fhir/T-TRTMNT</c>) or as an <c>xp</c> query parameter
/// (<c>https://example.org/fhir?xp=T-TRTMNT</c>). Change <see cref="Extract"/> when the format is published;
/// every caller (issuance checks, RA approval, bulk revocation) follows.
/// </summary>
public static partial class ExchangePurposeSan
{
    /// <summary>The <c>id-ce-subjectAltName</c> extension OID.</summary>
    private const string SanOid = "2.5.29.17";

    /// <summary>
    /// An exchange purpose code as listed in the TEFCA Exchange Purposes SOP: <c>T-</c> followed by one or more
    /// hyphen-separated upper-case segments (<c>T-TRTMNT</c>, <c>T-PH-ECR</c>, <c>T-IAS</c>).
    /// </summary>
    [GeneratedRegex("^T-[A-Z0-9]+(?:-[A-Z0-9]+)*$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex CodePattern();

    /// <summary>True when <paramref name="code"/> has the shape of an exchange purpose code.</summary>
    public static bool IsCode(string? code) => !string.IsNullOrWhiteSpace(code) && CodePattern().IsMatch(code.Trim());

    /// <summary>The code in its canonical (trimmed, upper-case) form, or null when it isn't one.</summary>
    public static string? Normalize(string? code) => IsCode(code) ? code!.Trim().ToUpperInvariant() : null;

    /// <summary>
    /// The exchange purpose code <paramref name="sanUri"/> carries, upper-case, or null when it carries none.
    /// The query parameter wins over the fragment, and the fragment over the last path segment.
    /// </summary>
    public static string? Extract(string? sanUri)
    {
        if (string.IsNullOrWhiteSpace(sanUri)) return null;
        var value = sanUri.Trim();

        string? fragment = null;
        var hash = value.IndexOf('#');
        if (hash >= 0)
        {
            fragment = value[(hash + 1)..];
            value = value[..hash];
        }

        string? query = null;
        var question = value.IndexOf('?');
        if (question >= 0)
        {
            query = value[(question + 1)..];
            value = value[..question];
        }

        if (query is not null)
        {
            foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = pair.IndexOf('=');
                if (eq <= 0) continue;
                if (!string.Equals(pair[..eq], "xp", StringComparison.OrdinalIgnoreCase)) continue;
                if (Normalize(Uri.UnescapeDataString(pair[(eq + 1)..])) is { } fromQuery) return fromQuery;
            }
        }

        if (Normalize(fragment) is { } fromFragment) return fromFragment;

        var slash = value.TrimEnd('/').LastIndexOf('/');
        return slash >= 0 ? Normalize(Uri.UnescapeDataString(value.TrimEnd('/')[(slash + 1)..])) : null;
    }

    /// <summary>The distinct exchange purpose codes carried by any of <paramref name="sanUris"/>.</summary>
    public static IReadOnlySet<string> ExtractAll(IEnumerable<string?> sanUris) =>
        sanUris.Select(Extract).OfType<string>().ToHashSet(StringComparer.Ordinal);

    /// <summary>The distinct exchange purpose codes carried by the URI entries in <paramref name="sans"/>.</summary>
    public static IReadOnlySet<string> ExtractAll(IEnumerable<ApiSanEntry> sans) =>
        ExtractAll(sans
            .Where(s => string.Equals(s.Type, "Uri", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Value));

    /// <summary>The exchange purpose codes carried by the URI SANs of <paramref name="certificate"/>.</summary>
    public static IReadOnlySet<string> ExtractAll(X509Certificate2 certificate) => ExtractAll(ReadSanUris(certificate));

    /// <summary>The <c>uniformResourceIdentifier</c> entries of a certificate's subjectAltName extension.</summary>
    public static IReadOnlyList<string> ReadSanUris(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions[SanOid];
        if (extension is null) return [];

        var uris = new List<string>();
        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var names = reader.ReadSequence();
            var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
            while (names.HasData)
            {
                var tag = names.PeekTag();
                if (tag.HasSameClassAndValue(uriTag))
                    uris.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag));
                else
                    names.ReadEncodedValue();
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension carries no usable URI.
        }

        return uris;
    }
}
