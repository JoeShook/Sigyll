#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;

namespace Sigyll.Common.Services;

/// <summary>
/// Rewrites distinguished name attribute names that OpenSSL prints but .NET's
/// <c>X500DistinguishedName</c> parser rejects, so a DN copied from openssl output parses.
///
/// RFC 4514 names only CN, L, ST, O, OU, C, STREET, DC and UID; every other attribute is written as its
/// OID. OpenSSL's <c>emailAddress</c> (PKCS #9, RFC 2985) becomes <c>E</c>, and <c>UID</c> (RFC 4519),
/// which .NET does not know by name, becomes its OID. Both forms also parse in BouncyCastle's X509Name.
/// Values, quoting and escapes are left as they are.
/// </summary>
public static class DistinguishedNameText
{
    private const string UidOid = "OID.0.9.2342.19200300.100.1.1";

    private static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["emailAddress"] = "E",
        ["UID"] = UidOid,
        ["userId"] = UidOid,
    };

    public static string Normalize(string dn)
    {
        var sb = new StringBuilder(dn.Length);
        var atName = true;
        var inQuotes = false;

        for (var i = 0; i < dn.Length; i++)
        {
            var c = dn[i];
            if (atName)
            {
                if (char.IsWhiteSpace(c))
                {
                    sb.Append(c);
                    continue;
                }

                var eq = dn.IndexOf('=', i);
                if (eq < 0)
                {
                    sb.Append(dn, i, dn.Length - i);
                    break;
                }

                var name = dn[i..eq];
                sb.Append(Aliases.TryGetValue(name.Trim(), out var alias) ? alias : name).Append('=');
                i = eq;
                atName = false;
                continue;
            }

            if (c == '\\' && i + 1 < dn.Length)
            {
                sb.Append(c).Append(dn[++i]);
                continue;
            }

            if (c == '"')
                inQuotes = !inQuotes;
            else if (!inQuotes && c is ',' or ';' or '+')
                atName = true;

            sb.Append(c);
        }

        return sb.ToString();
    }
}
