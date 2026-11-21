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

        /// <summary><c>...?xp=T-TRTMNT</c></summary>
        Query,
    }

    /// <summary>
    /// Finds an authorized XP code in <paramref name="sanUri"/> in any candidate form: the fragment, the last path
    /// segment, or an <c>xp</c> query parameter. Returns false when none of them holds a known code.
    /// </summary>
    public static bool TryFromSanUri(string? sanUri, out string code, out SanForm form)
    {
        code = string.Empty;
        form = default;
        if (string.IsNullOrWhiteSpace(sanUri))
            return false;

        var text = sanUri.Trim();

        var hash = text.IndexOf('#');
        if (hash >= 0)
        {
            var fragment = Uri.UnescapeDataString(text[(hash + 1)..]);
            if (Codes.Contains(fragment))
            {
                code = fragment;
                form = SanForm.Fragment;
                return true;
            }

            text = text[..hash];
        }

        var question = text.IndexOf('?');
        if (question >= 0)
        {
            foreach (var pair in text[(question + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var equals = pair.IndexOf('=');
                if (equals <= 0)
                    continue;
                var name = Uri.UnescapeDataString(pair[..equals]);
                var value = Uri.UnescapeDataString(pair[(equals + 1)..]);
                if (string.Equals(name, "xp", StringComparison.OrdinalIgnoreCase) && Codes.Contains(value))
                {
                    code = value;
                    form = SanForm.Query;
                    return true;
                }
            }

            text = text[..question];
        }

        var slash = text.LastIndexOf('/');
        if (slash >= 0 && slash < text.Length - 1)
        {
            var segment = Uri.UnescapeDataString(text[(slash + 1)..]);
            if (Codes.Contains(segment))
            {
                code = segment;
                form = SanForm.PathSegment;
                return true;
            }
        }

        return false;
    }
}
