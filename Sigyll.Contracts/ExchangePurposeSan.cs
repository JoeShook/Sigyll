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
/// How SAN URIs carry an exchange purpose. Bound from the <c>ExchangePurposeSan</c> configuration section of both the
/// CA and the RA portal, which must agree.
/// </summary>
public sealed class ExchangePurposeSanOptions
{
    public const string Section = "ExchangePurposeSan";

    /// <summary>
    /// Name of the query parameter that carries the exchange purpose, e.g. <c>?&lt;name&gt;=T-TRTMNT</c>, matched
    /// case-sensitively. The TEFCA client SAN format is not settled, so there is no default: unset, the query form is
    /// not recognised at all and only the fragment and last-path-segment forms are.
    /// </summary>
    public string? QueryParameterName { get; set; }
}

/// <summary>What <see cref="ExchangePurposeSan.Parse"/> found in one SAN URI.</summary>
/// <param name="Code">The exchange purpose code, or null when there is none or it is ambiguous.</param>
/// <param name="Ambiguous">True when the URI carries conflicting exchange purposes; <paramref name="Code"/> is then null.</param>
public readonly record struct ExchangePurposeMatch(string? Code, bool Ambiguous);

/// <summary>What <see cref="ExchangePurposeSan.Scan(IEnumerable{string?}, string?)"/> found in a set of SAN URIs.</summary>
/// <param name="Codes">The distinct exchange purpose codes carried unambiguously.</param>
/// <param name="AmbiguousSans">SAN URIs that carry conflicting exchange purposes, verbatim.</param>
public sealed record ExchangePurposeScan(IReadOnlySet<string> Codes, IReadOnlyList<string> AmbiguousSans);

/// <summary>
/// Reads the TEFCA exchange purpose (XP) code a SAN URI carries. The client SAN format is not settled, so this is the
/// one place that knows it; every caller (issuance checks, RA approval, bulk revocation) follows.
/// <para>
/// URIs are handled as HL7 SSRAA requires: as case-sensitive strings, never normalized, percent-decoded or re-encoded.
/// The raw string is split by hand: the fragment is everything after the first <c>#</c>; the query is everything
/// after the first <c>?</c> that comes before it; the path runs from the end of the authority (or of the scheme, for a
/// URN) to the query or fragment.
/// </para>
/// <para>
/// An exchange purpose may appear in any of three places, and each value must equal a code exactly
/// (<c>T-TRTMNT</c>, never <c>t-trtmnt</c> or <c>T%2DTRTMNT</c>):
/// the fragment (<c>urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT</c>); the last path segment
/// (<c>https://example.org/fhir/T-TRTMNT</c>); and, only when <see cref="ExchangePurposeSanOptions.QueryParameterName"/>
/// is configured, that query parameter (<c>https://example.org/fhir?&lt;name&gt;=T-TRTMNT</c>).
/// </para>
/// <para>
/// Precedence: none of the places outranks another. If more than one carries a code, they must all carry the same
/// one; different codes in different places, or the query parameter repeated with different values, make the URI
/// ambiguous, and it then carries no exchange purpose (<see cref="ExchangePurposeMatch.Ambiguous"/> is set so callers
/// can flag it).
/// </para>
/// </summary>
public static partial class ExchangePurposeSan
{
    /// <summary>The <c>id-ce-subjectAltName</c> extension OID.</summary>
    private const string SanOid = "2.5.29.17";

    /// <summary>
    /// An exchange purpose code as listed in the TEFCA Exchange Purposes SOP: <c>T-</c> followed by one or more
    /// hyphen-separated upper-case segments (<c>T-TRTMNT</c>, <c>T-PH-ECR</c>, <c>T-IAS</c>). Case-sensitive.
    /// </summary>
    [GeneratedRegex("^T-[A-Z0-9]+(?:-[A-Z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex CodePattern();

    /// <summary>True when <paramref name="value"/> is exactly an exchange purpose code.</summary>
    public static bool IsCode(string? value) => value is not null && CodePattern().IsMatch(value);

    /// <summary>A code typed by a person, with surrounding white space removed, or null when it isn't a code.</summary>
    public static string? Normalize(string? code) => code?.Trim() is { } trimmed && IsCode(trimmed) ? trimmed : null;

    /// <summary>The exchange purpose code <paramref name="sanUri"/> carries, or null when it carries none or it is ambiguous.</summary>
    public static string? Extract(string? sanUri, string? queryParameterName) => Parse(sanUri, queryParameterName).Code;

    /// <summary>Reads the exchange purpose of one SAN URI; see the class remarks for the rules.</summary>
    public static ExchangePurposeMatch Parse(string? sanUri, string? queryParameterName)
    {
        if (string.IsNullOrEmpty(sanUri)) return default;

        var rest = sanUri;
        string? fragment = null;
        var hash = rest.IndexOf('#');
        if (hash >= 0)
        {
            fragment = rest[(hash + 1)..];
            rest = rest[..hash];
        }

        string? query = null;
        var question = rest.IndexOf('?');
        if (question >= 0)
        {
            query = rest[(question + 1)..];
            rest = rest[..question];
        }

        var found = new HashSet<string>(StringComparer.Ordinal);

        if (IsCode(fragment)) found.Add(fragment!);

        var lastSegment = LastPathSegment(rest);
        if (IsCode(lastSegment)) found.Add(lastSegment!);

        if (query is not null && !string.IsNullOrEmpty(queryParameterName))
        {
            var values = new HashSet<string>(StringComparer.Ordinal);
            foreach (var pair in query.Split('&'))
            {
                var eq = pair.IndexOf('=');
                var name = eq >= 0 ? pair[..eq] : pair;
                if (!string.Equals(name, queryParameterName, StringComparison.Ordinal)) continue;
                values.Add(eq >= 0 ? pair[(eq + 1)..] : string.Empty);
            }

            if (values.Count > 1) return new ExchangePurposeMatch(null, Ambiguous: true);
            if (values.Count == 1 && IsCode(values.First())) found.Add(values.First());
        }

        return found.Count switch
        {
            0 => default,
            1 => new ExchangePurposeMatch(found.First(), Ambiguous: false),
            _ => new ExchangePurposeMatch(null, Ambiguous: true),
        };
    }

    /// <summary>The exchange purposes carried by <paramref name="sanUris"/>, and the ambiguous ones.</summary>
    public static ExchangePurposeScan Scan(IEnumerable<string?> sanUris, string? queryParameterName)
    {
        var codes = new HashSet<string>(StringComparer.Ordinal);
        var ambiguous = new List<string>();
        foreach (var uri in sanUris)
        {
            var match = Parse(uri, queryParameterName);
            if (match.Ambiguous) ambiguous.Add(uri!);
            else if (match.Code is not null) codes.Add(match.Code);
        }
        return new ExchangePurposeScan(codes, ambiguous);
    }

    /// <summary>The exchange purposes carried by the URI entries in <paramref name="sans"/>.</summary>
    public static ExchangePurposeScan Scan(IEnumerable<ApiSanEntry> sans, string? queryParameterName) =>
        Scan(sans
            .Where(s => string.Equals(s.Type, "Uri", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Value), queryParameterName);

    /// <summary>The exchange purposes carried by the URI SANs of <paramref name="certificate"/>.</summary>
    public static ExchangePurposeScan Scan(X509Certificate2 certificate, string? queryParameterName) =>
        Scan(ReadSanUris(certificate), queryParameterName);

    /// <summary>
    /// The last segment of the path part of <paramref name="beforeQuery"/> (the URI with query and fragment removed),
    /// or null when the path has no <c>/</c>. For <c>scheme://authority/path</c> the path starts at the first
    /// <c>/</c> after the authority; for a URN it is everything after the scheme.
    /// </summary>
    private static string? LastPathSegment(string beforeQuery)
    {
        var colon = beforeQuery.IndexOf(':');
        var path = colon >= 0 ? beforeQuery[(colon + 1)..] : beforeQuery;
        if (path.StartsWith("//", StringComparison.Ordinal))
        {
            var slash = path.IndexOf('/', 2);
            if (slash < 0) return null; // authority only, no path
            path = path[slash..];
        }

        var last = path.LastIndexOf('/');
        return last >= 0 ? path[(last + 1)..] : null;
    }

    /// <summary>The <c>uniformResourceIdentifier</c> entries of a certificate's subjectAltName extension, verbatim.</summary>
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
