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
using Shouldly;
using Sigyll.Common.Services;

namespace Sigyll.Signing.Tests;

public class CertificateExtensionHelpersTests
{
    [Theory]
    [InlineData("http://localhost:5034/crls/PQC Test Root (ML-DSA-87) (2).crl",
        "http://localhost:5034/crls/PQC%20Test%20Root%20(ML-DSA-87)%20(2).crl")]
    [InlineData("http://crl.fhircerts.net/crls/SureFhirLabs_Intermediate.crl",
        "http://crl.fhircerts.net/crls/SureFhirLabs_Intermediate.crl")]
    [InlineData("http://localhost:5034/crls/already%20encoded.crl",
        "http://localhost:5034/crls/already%20encoded.crl")]
    public void MakeCdp_PercentEncodesUrls_LikeAia(string url, string expected)
    {
        var cdp = CertificateExtensionHelpers.MakeCdp(url);

        var reader = new AsnReader(cdp.RawData, AsnEncodingRules.DER)
            .ReadSequence().ReadSequence()
            .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true))
            .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        reader.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6))
            .ShouldBe(expected);

        var aia = CertificateExtensionHelpers.BuildAiaExtension(new Uri(url.Replace("/crls/", "/certs/")));
        System.Text.Encoding.ASCII.GetString(aia.RawData).ShouldContain(expected.Replace("/crls/", "/certs/"));
    }
}
