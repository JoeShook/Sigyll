#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using Sigyll.Contracts;
using Xunit;

namespace Sigyll.Signing.Tests;

public class ExchangePurposeSanTests
{
    // A stand-in for whatever query parameter name gets configured; deliberately not a real or proposed name.
    private const string Param = "purpose-param";

    [Theory]
    [InlineData("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://fhir.example.org/r4#T-PYMNT", "T-PYMNT")]
    [InlineData("https://fhir.example.org/r4/T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://fhir.example.org/r4/T-PH-ECR", "T-PH-ECR")]
    [InlineData("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1/T-IAS", "T-IAS")]
    [InlineData("https://fhir.example.org/r4/T-TRTMNT#T-TRTMNT", "T-TRTMNT")]
    public void FragmentAndPathForms_WorkWithoutConfiguration(string san, string expected)
    {
        ExchangePurposeSan.Extract(san, queryParameterName: null).ShouldBe(expected);
        ExchangePurposeSan.Extract(san, Param).ShouldBe(expected);
    }

    [Theory]
    [InlineData("https://fhir.example.org/r4?purpose-param=T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://fhir.example.org/r4?app=one&purpose-param=T-HCO", "T-HCO")]
    [InlineData("https://fhir.example.org/r4?purpose-param=T-HCO&purpose-param=T-HCO", "T-HCO")]
    [InlineData("https://fhir.example.org/r4/T-HCO?purpose-param=T-HCO#T-HCO", "T-HCO")]
    public void QueryForm_UsesTheConfiguredName(string san, string expected)
    {
        ExchangePurposeSan.Extract(san, Param).ShouldBe(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void QueryForm_IsIgnoredWhenNoNameIsConfigured(string? name)
    {
        ExchangePurposeSan.Parse("https://fhir.example.org/r4?purpose-param=T-TRTMNT", name)
            .ShouldBe(new ExchangePurposeMatch(null, false));
    }

    [Fact]
    public void QueryForm_NameIsCaseSensitive()
    {
        ExchangePurposeSan.Extract("https://fhir.example.org/r4?Purpose-Param=T-TRTMNT", Param).ShouldBeNull();
    }

    [Fact]
    public void QueryForm_ValueIsNotPercentDecoded()
    {
        ExchangePurposeSan.Extract("https://fhir.example.org/r4?purpose-param=T%2DTRTMNT", Param).ShouldBeNull();
    }

    [Fact]
    public void QueryForm_RepeatedWithDifferentValues_IsAmbiguous()
    {
        ExchangePurposeSan.Parse("https://fhir.example.org/r4?purpose-param=T-TRTMNT&purpose-param=T-PYMNT", Param)
            .ShouldBe(new ExchangePurposeMatch(null, true));
    }

    [Theory]
    [InlineData("https://x.example/T-IAS#T-HCO", null)]
    [InlineData("https://x.example/fhir?purpose-param=T-PYMNT#T-HCO", Param)]
    [InlineData("https://x.example/T-IAS?purpose-param=T-PYMNT", Param)]
    public void DifferentCodesInDifferentPlaces_AreAmbiguous(string san, string? name)
    {
        ExchangePurposeSan.Parse(san, name).ShouldBe(new ExchangePurposeMatch(null, true));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://fhir.example.org")]
    [InlineData("https://fhir.example.org/r4")]
    [InlineData("https://fhir.example.org/r4#section-2")]
    [InlineData("https://fhir.example.org/r4/T-PH-ECR/")]     // trailing slash: the last segment is empty
    [InlineData("urn:oid:1.2.3#t-trtmnt")]                   // codes are case-sensitive
    [InlineData("https://fhir.example.org/r4/t-trtmnt")]
    [InlineData("https://fhir.example.org/r4/T%2DTRTMNT")]   // never percent-decoded
    [InlineData("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1")]
    [InlineData("T-TRTMNT")]
    [InlineData("https://T-TRTMNT")]                         // authority, not path
    public void ReturnsNullWhenNoExchangePurpose(string? san)
    {
        ExchangePurposeSan.Parse(san, Param).ShouldBe(new ExchangePurposeMatch(null, false));
    }

    [Fact]
    public void Scan_IgnoresNonUriEntries_AndReportsAmbiguousSans()
    {
        var sans = new List<ApiSanEntry>
        {
            new() { Type = "Uri", Value = "urn:oid:1.2.3#T-TRTMNT" },
            new() { Type = "uri", Value = "urn:oid:1.2.3#T-TRTMNT" },
            new() { Type = "Uri", Value = "https://x.example/fhir?purpose-param=T-PYMNT" },
            new() { Type = "Uri", Value = "https://x.example/T-IAS#T-HCO" },
            new() { Type = "Dns", Value = "T-HCO" },
        };

        var scan = ExchangePurposeSan.Scan(sans, Param);

        scan.Codes.Order().ShouldBe(["T-PYMNT", "T-TRTMNT"]);
        scan.AmbiguousSans.ShouldBe(["https://x.example/T-IAS#T-HCO"]);
        ExchangePurposeSan.Scan(sans, null).Codes.ShouldBe(["T-TRTMNT"]);
    }

    [Fact]
    public void Scan_ReadsTheCertificateSanUris()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT"));
        san.AddDnsName("client.example.org");
        san.AddUri(new Uri("https://fhir.example.org/r4"));
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        ExchangePurposeSan.ReadSanUris(cert).Count.ShouldBe(2);
        ExchangePurposeSan.Scan(cert, null).Codes.ShouldBe(["T-TRTMNT"]);
    }

    [Theory]
    [InlineData("T-TRTMNT", true)]
    [InlineData("T-PH-ECR", true)]
    [InlineData("t-pymnt", false)]
    [InlineData(" T-PYMNT", false)]
    [InlineData("TRTMNT", false)]
    [InlineData("T-", false)]
    [InlineData("T-TRT MNT", false)]
    public void IsCode_IsExact(string code, bool expected)
    {
        ExchangePurposeSan.IsCode(code).ShouldBe(expected);
    }

    [Fact]
    public void Normalize_TrimsTypedInputButKeepsCase()
    {
        ExchangePurposeSan.Normalize(" T-TRTMNT ").ShouldBe("T-TRTMNT");
        ExchangePurposeSan.Normalize("t-trtmnt").ShouldBeNull();
    }
}
