#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Services.Tefca;

/// <summary>
/// TEFCA Exchange Purpose (XP) codes and the ways a client certificate's SAN URI may carry one. Kept internal: the
/// SAN form for TEFCA client certificates is not settled, so this is a conformance aid, not an API.
/// </summary>
/// <remarks>
/// URIs follow the HL7 SSRAA 3.0.0 rules: a SAN is compared as a case-sensitive string with no normalization. The
/// raw SAN text is split on its delimiters only; nothing is percent-decoded, case-folded or trimmed, and an XP
/// code must match exactly.
/// </remarks>
internal static class TefcaExchangePurpose
{
    /// <summary>The OID of the TEFCA Exchange Purpose code system.</summary>
    public const string CodeSystemOid = "2.16.840.1.113883.3.7204.1.5.2.1";

    /// <summary>The authorized XP codes (Exchange Purposes (XPs) SOP v5.1, Table 1).</summary>
    public static readonly IReadOnlySet<string> Codes = new HashSet<string>(StringComparer.Ordinal)
    {
        "T-TREAT", "T-TRTMNT", "T-PYMNT",
        "T-HCO", "T-HCO-CC", "T-HCO-HED", "T-HCO-QAI", "T-HCO-POP", "T-HCO-PTSAFETY", "T-HCO-PERF",
        "T-PH", "T-PH-ECR", "T-PH-ELR",
        "T-IAS",
        "T-GOVDTRM", "T-GOVDTRM-SSD", "T-GOVDTRM-ACP",
    };

    /// <summary>Where in a SAN URI an exchange purpose code was found.</summary>
    public enum SanForm
    {
        /// <summary><c>...#T-TRTMNT</c></summary>
        Fragment,

        /// <summary><c>.../T-TRTMNT</c> (the last path segment)</summary>
        PathSegment,

        /// <summary><c>...?{name}=T-TRTMNT</c>, where <c>{name}</c> is configured</summary>
        Query,
    }

    /// <summary>What a SAN URI says about its exchange purpose.</summary>
    public enum Outcome
    {
        Found,
        NotFound,

        /// <summary>The configured query parameter appears more than once with different values.</summary>
        Ambiguous,
    }

    /// <summary>
    /// Looks for an authorized XP code in the raw <paramref name="sanUri"/>: the fragment, then a query parameter
    /// named <paramref name="queryParameterName"/> (only when one is configured), then the last path segment.
    /// The parameter name compares ordinally and values are taken verbatim.
    /// </summary>
    public static Outcome FromSanUri(string? sanUri, string? queryParameterName, out string code, out SanForm form)
    {
        code = string.Empty;
        form = default;
        if (string.IsNullOrEmpty(sanUri))
            return Outcome.NotFound;

        // Split the raw text: fragment after the first '#', query after the first '?' before it, path before that.
        var hash = sanUri.IndexOf('#');
        var fragment = hash >= 0 ? sanUri[(hash + 1)..] : null;
        var beforeFragment = hash >= 0 ? sanUri[..hash] : sanUri;
        var question = beforeFragment.IndexOf('?');
        var query = question >= 0 ? beforeFragment[(question + 1)..] : null;
        var path = question >= 0 ? beforeFragment[..question] : beforeFragment;

        // Values of the configured query parameter, taken verbatim. Conflicting duplicates make the SAN ambiguous,
        // whatever else it carries.
        var values = new List<string>();
        if (query != null && !string.IsNullOrEmpty(queryParameterName))
        {
            foreach (var pair in query.Split('&'))
            {
                var equals = pair.IndexOf('=');
                if (equals > 0 && string.Equals(pair[..equals], queryParameterName, StringComparison.Ordinal)
                    && !values.Contains(pair[(equals + 1)..], StringComparer.Ordinal))
                    values.Add(pair[(equals + 1)..]);
            }
        }

        if (values.Count > 1)
            return Outcome.Ambiguous;

        if (fragment != null && Codes.Contains(fragment))
        {
            code = fragment;
            form = SanForm.Fragment;
            return Outcome.Found;
        }

        if (values.Count == 1 && Codes.Contains(values[0]))
        {
            code = values[0];
            form = SanForm.Query;
            return Outcome.Found;
        }

        var slash = path.LastIndexOf('/');
        if (slash >= 0 && slash < path.Length - 1 && Codes.Contains(path[(slash + 1)..]))
        {
            code = path[(slash + 1)..];
            form = SanForm.PathSegment;
            return Outcome.Found;
        }

        return Outcome.NotFound;
    }
}
