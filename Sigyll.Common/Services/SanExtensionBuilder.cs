#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Sigyll.Common.ViewModels;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigyll.Common.Services;

/// <summary>
/// Builds the Subject Alternative Name extension with the name text exactly as supplied.
///
/// .NET's <c>SubjectAlternativeNameBuilder.AddUri</c> stores <c>Uri.AbsoluteUri</c>, which
/// normalises the value — most visibly by appending "/" to a URI with an empty path, so
/// <c>https://host</c> becomes <c>https://host/</c>. UDAP relying parties compare the SAN URI
/// to the client's base URL byte-for-byte, so the extension must carry what the operator typed.
/// </summary>
public static class SanExtensionBuilder
{
    public const string SubjectAltNameOid = "2.5.29.17";

    /// <summary>
    /// Builds a non-critical SAN extension from the entries. Values are trimmed but otherwise
    /// untouched. URIs must be absolute and IP addresses must parse; DNS and email are taken as-is.
    /// Returns null when there are no non-empty entries.
    /// </summary>
    public static X509Extension? Build(IEnumerable<SanEntry> entries, bool critical = false)
    {
        var names = new List<GeneralName>();

        foreach (var entry in entries)
        {
            var value = entry.Value?.Trim();
            if (string.IsNullOrEmpty(value)) continue;

            switch (entry.Type)
            {
                case SanType.Uri:
                    if (!Uri.TryCreate(value, UriKind.Absolute, out _))
                        throw new ArgumentException($"'{value}' is not an absolute URI.");
                    names.Add(new GeneralName(GeneralName.UniformResourceIdentifier, value));
                    break;

                case SanType.Dns:
                    names.Add(new GeneralName(GeneralName.DnsName, value));
                    break;

                case SanType.Email:
                    names.Add(new GeneralName(GeneralName.Rfc822Name, value));
                    break;

                case SanType.IpAddress:
                    if (!IPAddress.TryParse(value, out var ip))
                        throw new ArgumentException($"'{value}' is not a valid IP address.");
                    names.Add(new GeneralName(GeneralName.IPAddress, new Org.BouncyCastle.Asn1.DerOctetString(ip.GetAddressBytes())));
                    break;
            }
        }

        if (names.Count == 0) return null;

        var generalNames = new GeneralNames(names.ToArray());
        return new X509Extension(new Oid(SubjectAltNameOid, "Subject Alternative Name"), generalNames.GetDerEncoded(), critical);
    }
}
