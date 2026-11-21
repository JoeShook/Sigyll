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
    [Theory]
    [InlineData("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1#T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://fhir.example.org/r4#T-PYMNT", "T-PYMNT")]
    [InlineData("https://fhir.example.org/r4/T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://fhir.example.org/r4/T-PH-ECR/", "T-PH-ECR")]
    [InlineData("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1/T-IAS", "T-IAS")]
    [InlineData("https://fhir.example.org/r4?xp=T-TRTMNT", "T-TRTMNT")]
    [InlineData("https://fhir.example.org/r4?app=one&XP=t-hco", "T-HCO")]
    [InlineData("https://fhir.example.org/r4?xp=T%2DTRTMNT", "T-TRTMNT")]
    [InlineData("urn:oid:1.2.3#t-trtmnt", "T-TRTMNT")]
    public void Extract_ReadsEveryForm(string san, string expected)
    {
        ExchangePurposeSan.Extract(san).ShouldBe(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://fhir.example.org/r4")]
    [InlineData("https://fhir.example.org/r4#section-2")]
    [InlineData("https://fhir.example.org/r4?xp=")]
    [InlineData("https://fhir.example.org/r4?other=T-TRTMNT")]
    [InlineData("urn:oid:2.16.840.1.113883.3.7204.1.5.2.1")]
    [InlineData("T-TRTMNT")]
    public void Extract_ReturnsNullWhenNoExchangePurpose(string? san)
    {
        ExchangePurposeSan.Extract(san).ShouldBeNull();
    }

    [Fact]
    public void Extract_QueryWinsOverFragmentAndPath()
    {
        ExchangePurposeSan.Extract("https://x.example/T-IAS?xp=T-PYMNT#T-HCO").ShouldBe("T-PYMNT");
        ExchangePurposeSan.Extract("https://x.example/T-IAS#T-HCO").ShouldBe("T-HCO");
    }

    [Fact]
    public void ExtractAll_IgnoresNonUriEntries()
    {
        var sans = new List<ApiSanEntry>
        {
            new() { Type = "Uri", Value = "urn:oid:1.2.3#T-TRTMNT" },
            new() { Type = "uri", Value = "urn:oid:1.2.3#T-TRTMNT" },
            new() { Type = "Uri", Value = "https://x.example/fhir?xp=T-PYMNT" },
            new() { Type = "Dns", Value = "T-HCO" },
        };

        ExchangePurposeSan.ExtractAll(sans).Order().ShouldBe(["T-PYMNT", "T-TRTMNT"]);
    }

    [Fact]
    public void ExtractAll_ReadsTheCertificateSanUris()
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
        ExchangePurposeSan.ExtractAll(cert).ShouldBe(["T-TRTMNT"]);
    }

    [Theory]
    [InlineData("T-TRTMNT", true)]
    [InlineData(" t-pymnt ", true)]
    [InlineData("T-PH-ECR", true)]
    [InlineData("TRTMNT", false)]
    [InlineData("T-", false)]
    [InlineData("T-TRT MNT", false)]
    public void IsCode(string code, bool expected)
    {
        ExchangePurposeSan.IsCode(code).ShouldBe(expected);
    }
}
