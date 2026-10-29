#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Components.Account;

/// <summary>Recovery codes as operators type or paste them.</summary>
public static class RecoveryCodes
{
    /// <summary>
    /// Identity issues codes as XXXXX-XXXXX in upper case and matches them exactly; accept them typed in any case,
    /// with or without the dash or spaces.
    /// </summary>
    public static string Normalize(string input)
    {
        var code = new string(input.Where(c => c is not (' ' or '-')).ToArray()).ToUpperInvariant();
        return code.Length == 10 ? $"{code[..5]}-{code[5..]}" : code;
    }
}
