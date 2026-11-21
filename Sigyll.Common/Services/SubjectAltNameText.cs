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
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Sigyll.Common.ViewModels;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigyll.Common.Services;

/// <summary>
/// Display text for a Subject Alternative Name extension.
/// </summary>
public static class SubjectAltNameText
{
    /// <summary>
    /// Describes each name in the SAN extension, one line per name.
    ///
    /// .NET's <c>X509Extension.Format</c> is used as before, except when the extension holds an
    /// otherName: the platform formatters render those as hex or "&lt;unsupported&gt;", so the
    /// whole extension is described here instead, in the same <c>Type:value</c> form Sigyll
    /// stores for certificates it issues (e.g. <c>Npi:1234567893</c>, <c>Dns:example.com</c>).
    /// Returns an empty list when the extension cannot be read.
    /// </summary>
    public static List<string> Describe(X509Extension sanExtension)
    {
        var decoded = TryDescribeOtherNames(sanExtension.RawData);
        if (decoded != null) return decoded;

        try
        {
            return sanExtension.Format(multiLine: true)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Returns the BouncyCastle-decoded description when the extension contains at least one
    /// otherName; null otherwise (or when it cannot be decoded).
    /// </summary>
    private static List<string>? TryDescribeOtherNames(byte[] rawData)
    {
        GeneralName[] names;
        try
        {
            names = GeneralNames.GetInstance(Asn1Object.FromByteArray(rawData)).GetNames();
        }
        catch
        {
            return null;
        }

        if (!names.Any(n => n.TagNo == GeneralName.OtherName)) return null;

        var lines = new List<string>();
        foreach (var gn in names)
        {
            try
            {
                lines.Add(DescribeName(gn));
            }
            catch
            {
                lines.Add($"[{gn.TagNo}]: (unreadable)");
            }
        }
        return lines;
    }

    private static string DescribeName(GeneralName gn)
    {
        switch (gn.TagNo)
        {
            case GeneralName.OtherName:
                if (NpiNumber.TryRead(gn, out var npi))
                    return $"{SanType.Npi}:{npi}";
                var (oid, value) = NpiNumber.ReadOtherName(gn);
                return value is IAsn1String text
                    ? $"OtherName:{oid}={text.GetString()}"
                    : $"OtherName:{oid}";
            case GeneralName.UniformResourceIdentifier:
                return $"{SanType.Uri}:{DerIA5String.GetInstance(gn.Name).GetString()}";
            case GeneralName.DnsName:
                return $"{SanType.Dns}:{DerIA5String.GetInstance(gn.Name).GetString()}";
            case GeneralName.Rfc822Name:
                return $"{SanType.Email}:{DerIA5String.GetInstance(gn.Name).GetString()}";
            case GeneralName.IPAddress:
                return $"{SanType.IpAddress}:{new IPAddress(Asn1OctetString.GetInstance(gn.Name).GetOctets())}";
            case GeneralName.DirectoryName:
                return $"DirName:{X509Name.GetInstance(gn.Name)}";
            default:
                return $"[{gn.TagNo}]";
        }
    }
}
