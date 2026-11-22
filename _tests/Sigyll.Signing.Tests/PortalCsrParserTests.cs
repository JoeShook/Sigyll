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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;
using Sigyll.Portal.Services;

namespace Sigyll.Signing.Tests;

public class PortalCsrParserTests
{
    [Fact]
    public void Parse_ReadsEverySanTypeThePortalCanRequest()
    {
        var pem = CsrWithSans(
            new SanEntry(SanType.Uri, "https://fhir.example.org/fhir/r4"),
            new SanEntry(SanType.Dns, "fhir.example.org"),
            new SanEntry(SanType.Email, "ops@example.org"),
            new SanEntry(SanType.IpAddress, "10.1.2.3"),
            new SanEntry(SanType.Npi, "1234567893"));

        var parsed = CsrParser.Parse(pem);

        parsed.SubjectDn.ShouldBe("CN=fhir.example.org");
        parsed.Sans.Select(s => (s.Type, s.Value)).ShouldBe(
        [
            ("Uri", "https://fhir.example.org/fhir/r4"),
            ("Dns", "fhir.example.org"),
            ("Email", "ops@example.org"),
            ("IpAddress", "10.1.2.3"),
            ("Npi", "1234567893"),
        ]);
    }

    [Fact]
    public void Parse_KeepsUriSanVerbatim()
    {
        // SSRAA compares the SAN URI to the client's iss as an exact string, so no trailing slash may be added.
        var parsed = CsrParser.Parse(CsrWithSans(new SanEntry(SanType.Uri, "https://client.example.org")));

        parsed.Sans.ShouldHaveSingleItem().Value.ShouldBe("https://client.example.org");
    }

    [Fact]
    public void ReadSubjectAltNames_SkipsOtherNamesThatAreNotNpi()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                writer.WriteObjectIdentifier("1.3.6.1.4.1.311.20.2.3"); // Microsoft UPN
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "user@example.org");
            }
            writer.WriteCharacterString(UniversalTagNumber.IA5String, "fhir.example.org",
                new Asn1Tag(TagClass.ContextSpecific, 2));
        }

        var sans = CsrParser.ReadSubjectAltNames(writer.Encode());

        sans.ShouldHaveSingleItem().Type.ShouldBe("Dns");
    }

    [Theory]
    [InlineData("Dns", "DNS")]
    [InlineData("Uri", "URI")]
    [InlineData("IpAddress", "IP Address")]
    [InlineData("Npi", "NPI")]
    public void SanTypeDisplayName_ShowsFriendlyLabels(string token, string label)
    {
        CsrParser.SanTypeDisplayName(token).ShouldBe(label);
    }

    private static string CsrWithSans(params SanEntry[] sans)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=fhir.example.org", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(SanExtensionBuilder.Build(sans)!);
        return request.CreateSigningRequestPem();
    }
}
