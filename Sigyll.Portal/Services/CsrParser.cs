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
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Sigyll.Contracts;

namespace Sigyll.Portal.Services;

/// <summary>
/// Parses a caller-supplied PKCS#10 CSR for display/prefill in the request wizard — subject DN and
/// the SANs the portal can request (DNS, URI, email, IP address and NPI otherName). The portal only
/// reads the CSR (public material); it never handles the private key.
/// </summary>
public static class CsrParser
{
    /// <summary>otherName type-id for a National Provider Identifier (DirectTrust certificate profiles).</summary>
    public const string NpiOtherNameOid = "2.16.840.1.113883.4.6";

    public record ParsedCsr(string SubjectDn, List<ApiSanEntry> Sans);

    /// <summary>Label shown for a SAN type token in the request form.</summary>
    public static string SanTypeDisplayName(string type) => type switch
    {
        "Dns" => "DNS",
        "Uri" => "URI",
        "Email" => "Email",
        "IpAddress" => "IP Address",
        "Npi" => "NPI",
        _ => type
    };

    public static ParsedCsr Parse(string csrPem)
    {
        var req = CertificateRequest.LoadSigningRequestPem(
            csrPem,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        var sans = new List<ApiSanEntry>();
        foreach (var ext in req.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>())
            sans.AddRange(ReadSubjectAltNames(ext.RawData));

        return new ParsedCsr(req.SubjectName.Name, sans);
    }

    /// <summary>
    /// Reads the GeneralNames in a SAN extension value, in order. Name forms the portal cannot request
    /// are skipped, and so is an otherName other than a 10-digit NPI. The CA validates every value
    /// again (including the NPI check digit) when the request is issued.
    /// </summary>
    public static List<ApiSanEntry> ReadSubjectAltNames(ReadOnlyMemory<byte> sanExtensionValue)
    {
        var result = new List<ApiSanEntry>();
        var names = new AsnReader(sanExtensionValue, AsnEncodingRules.DER).ReadSequence();

        while (names.HasData)
        {
            var tag = names.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific)
            {
                names.ReadEncodedValue();
                continue;
            }

            switch (tag.TagValue)
            {
                case 0 when TryReadNpi(names.ReadSequence(tag), out var npi):
                    result.Add(new ApiSanEntry { Type = "Npi", Value = npi });
                    break;
                case 1:
                    result.Add(new ApiSanEntry { Type = "Email", Value = names.ReadCharacterString(UniversalTagNumber.IA5String, tag) });
                    break;
                case 2:
                    result.Add(new ApiSanEntry { Type = "Dns", Value = names.ReadCharacterString(UniversalTagNumber.IA5String, tag) });
                    break;
                case 6:
                    result.Add(new ApiSanEntry { Type = "Uri", Value = names.ReadCharacterString(UniversalTagNumber.IA5String, tag) });
                    break;
                case 7:
                    var octets = names.ReadOctetString(tag);
                    if (octets.Length is 4 or 16)
                        result.Add(new ApiSanEntry { Type = "IpAddress", Value = new IPAddress(octets).ToString() });
                    break;
                case 0:
                    break; // otherName that is not an NPI: already consumed by the guard above
                default:
                    names.ReadEncodedValue();
                    break;
            }
        }

        return result;
    }

    // otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
    private static bool TryReadNpi(AsnReader otherName, out string npi)
    {
        npi = "";
        if (otherName.ReadObjectIdentifier() != NpiOtherNameOid || !otherName.HasData)
            return false;

        var value = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        if (value.PeekTag() != new Asn1Tag(UniversalTagNumber.UTF8String))
            return false;

        var text = value.ReadCharacterString(UniversalTagNumber.UTF8String).Trim();
        if (text.Length != 10 || !text.All(char.IsAsciiDigit))
            return false;

        npi = text;
        return true;
    }
}
