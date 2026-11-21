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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Shouldly;
using Sigyll.Common.Services;
using Sigyll.Common.Validators;
using Sigyll.Common.ViewModels;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigyll.Signing.Tests;

public class NpiSanTests
{
    private readonly IssuanceValidator _validator = new();

    [Theory]
    [InlineData("1234567893")] // the worked example in the NPI check-digit standard
    [InlineData("1245319599")]
    [InlineData("1003000126")]
    public void IsValid_AcceptsNpisWithCorrectCheckDigit(string npi)
    {
        NpiNumber.IsValid(npi).ShouldBeTrue();
        NpiNumber.Validate(npi).ShouldBeNull();
    }

    [Theory]
    [InlineData("1234567890")]
    [InlineData("1234567894")]
    [InlineData("1245319590")]
    public void Validate_RejectsWrongCheckDigit(string npi)
    {
        NpiNumber.IsValid(npi).ShouldBeFalse();
        NpiNumber.Validate(npi)!.ShouldContain("check digit");
    }

    [Theory]
    [InlineData("")]
    [InlineData("123456789")]
    [InlineData("12345678930")]
    [InlineData("12345a7893")]
    [InlineData("123-456-78")]
    public void Validate_RejectsAnythingButTenDigits(string npi)
    {
        NpiNumber.IsValid(npi).ShouldBeFalse();
        NpiNumber.Validate(npi)!.ShouldContain("10 digits");
    }

    [Fact]
    public void ValidateSanValues_ChecksNpiEntries()
    {
        _validator.ValidateSanValues([new SanEntry(SanType.Npi, "1234567893")]).ShouldBeNull();
        _validator.ValidateSanValues([new SanEntry(SanType.Npi, " 1234567893 ")]).ShouldBeNull();
        _validator.ValidateSanValues([new SanEntry(SanType.Npi, "1234567890")])!.ShouldContain("NPI");
    }

    [Fact]
    public void ParseSanTypes_KnowsNpi()
    {
        IssuanceValidator.ParseSanTypes("DNS;NPI").ShouldBe([SanType.Dns, SanType.Npi]);
        IssuanceValidator.ParseSanTypeToken("npi").ShouldBe(SanType.Npi);
        IssuanceValidator.SanTypeDisplayName(SanType.Npi).ShouldBe("NPI");
    }

    [Fact]
    public void Build_EncodesNpiAsUtf8OtherName()
    {
        var ext = SanExtensionBuilder.Build([new SanEntry(SanType.Npi, " 1234567893 ")])!;

        var name = GeneralNames.GetInstance(Asn1Object.FromByteArray(ext.RawData)).GetNames().Single();
        name.TagNo.ShouldBe(GeneralName.OtherName);

        var seq = Asn1Sequence.GetInstance(name.Name);
        DerObjectIdentifier.GetInstance(seq[0]).Id.ShouldBe("2.16.840.1.113883.4.6");
        var tagged = Asn1TaggedObject.GetInstance(seq[1]);
        tagged.TagNo.ShouldBe(0);
        tagged.IsExplicit().ShouldBeTrue();
        var value = tagged.GetExplicitBaseObject().ShouldBeOfType<DerUtf8String>();
        value.GetString().ShouldBe("1234567893");
    }

    [Fact]
    public void Build_RejectsInvalidNpi()
    {
        Should.Throw<ArgumentException>(() => SanExtensionBuilder.Build([new SanEntry(SanType.Npi, "1234567890")]));
    }

    [Fact]
    public void Certificate_NpiSan_IsReadBackForReissueAndDisplay()
    {
        using var cert = SelfSigned(
        [
            new SanEntry(SanType.Uri, "https://host.example"),
            new SanEntry(SanType.Npi, "1245319599"),
        ]);

        CsrGenerationService.ExtractSubjectAltNames(cert).ShouldBe(
        [
            new SanEntry(SanType.Uri, "https://host.example"),
            new SanEntry(SanType.Npi, "1245319599"),
        ]);

        SubjectAltNameText.Describe(cert.Extensions[SanExtensionBuilder.SubjectAltNameOid]!)
            .ShouldBe(["Uri:https://host.example", "Npi:1245319599"]);
    }

    [Fact]
    public void Describe_WithoutOtherName_KeepsPlatformFormatting()
    {
        using var cert = SelfSigned([new SanEntry(SanType.Dns, "api.example.com")]);
        var ext = cert.Extensions[SanExtensionBuilder.SubjectAltNameOid]!;

        var expected = ext.Format(multiLine: true)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        SubjectAltNameText.Describe(ext).ShouldBe(expected);
    }

    [Fact]
    public void Describe_OtherNameThatIsNotNpi_ShowsItsOid()
    {
        var other = new GeneralName(GeneralName.OtherName, new DerSequence(
            new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
            new DerTaggedObject(true, 0, new DerUtf8String("user@example.com"))));
        var raw = new GeneralNames([other, new GeneralName(GeneralName.DnsName, "a.example")]).GetDerEncoded();

        var lines = SubjectAltNameText.Describe(new X509Extension(SanExtensionBuilder.SubjectAltNameOid, raw, false));

        lines.ShouldBe(["OtherName:1.3.6.1.4.1.311.20.2.3=user@example.com", "Dns:a.example"]);
    }

    private static X509Certificate2 SelfSigned(List<SanEntry> sans)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=npi.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(SanExtensionBuilder.Build(sans)!);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
