#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;

namespace Sigyll.Tests;

/// <summary>
/// What an enforced content security policy of <c>script-src 'self'</c> refuses in a page: an inline script block
/// (an import map counts), an inline event handler or a javascript: link.
/// </summary>
public static partial class InlineScripts
{
    public static IReadOnlyList<string> In(string html) =>
        [.. InlineBlocks().Matches(html).Select(m => m.Value.Length > 120 ? m.Value[..120] + "…" : m.Value),
         .. Handlers().Matches(html).Select(m => m.Value)];

    // <script> with a body and no src attribute.
    [GeneratedRegex("""<script(?![^>]*\bsrc=)[^>]*>\s*\S.*?</script>""", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex InlineBlocks();

    [GeneratedRegex("""\son[a-z]+\s*=\s*["']|href\s*=\s*["']\s*javascript:""", RegexOptions.IgnoreCase)]
    private static partial Regex Handlers();
}
