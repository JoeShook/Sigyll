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
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Xunit;
using BcCertificatePolicies = Org.BouncyCastle.Asn1.X509.CertificatePolicies;
using BcPolicyInformation = Org.BouncyCastle.Asn1.X509.PolicyInformation;
using BcPolicyQualifierInfo = Org.BouncyCastle.Asn1.X509.PolicyQualifierInfo;

namespace Sigyll.Signing.Tests;

public class CertificatePolicyExtensionTests
{
    private const string PolicyA = "1.3.6.1.4.1.99999.1.2";
    private const string PolicyB = "2.23.140.1.2.1";

    [Theory]
    [InlineData(PolicyA, true)]
    [InlineData(PolicyB, true)]
    [InlineData("2.5.29.32.0", true)]
    [InlineData("2.999", true)]
    [InlineData("1.39.1", true)]
    [InlineData("1.40.1", false)]
    [InlineData("3.1", false)]
    [InlineData("1", false)]
    [InlineData("1.3.06.1", false)]
    [InlineData("1.3.", false)]
    [InlineData("anyPolicy", false)]
    [InlineData("", false)]
    public void IsValidOid(string oid, bool expected) =>
        CertificatePolicyExtension.IsValidOid(oid).ShouldBe(expected);

    [Fact]
    public void Parse_AcceptsCommonSeparators_DropsBlanksAndRepeats_KeepsOrder()
    {
        CertificatePolicyExtension.Parse($" {PolicyB} ;{PolicyA}, {PolicyB}\n;; ")
            .ShouldBe([PolicyB, PolicyA]);
        CertificatePolicyExtension.Parse(null).ShouldBeEmpty();
        CertificatePolicyExtension.Parse("   ").ShouldBeEmpty();
    }

    [Fact]
    public void Normalize_JoinsWithSemicolons_OrNullWhenEmpty()
    {
        CertificatePolicyExtension.Normalize($"{PolicyA}, {PolicyB}").ShouldBe($"{PolicyA};{PolicyB}");
        CertificatePolicyExtension.Normalize(" ; ").ShouldBeNull();
    }

    [Fact]
    public void FindInvalid_NamesTheEntriesThatAreNotOids()
    {
        CertificatePolicyExtension.FindInvalid($"{PolicyA};nope;1.40.2").ShouldBe(["nope", "1.40.2"]);
        CertificatePolicyExtension.FindInvalid(PolicyA).ShouldBeEmpty();
    }

    [Fact]
    public void Build_NoPolicies_ReturnsNull()
    {
        CertificatePolicyExtension.Build((string?)null).ShouldBeNull();
        CertificatePolicyExtension.Build(Array.Empty<string>()).ShouldBeNull();
    }

    [Fact]
    public void Build_InvalidOid_Throws()
    {
        Should.Throw<ArgumentException>(() => CertificatePolicyExtension.Build([PolicyA, "not-an-oid"]));
    }

    [Fact]
    public void Build_WritesDerThatBouncyCastleReadsBack()
    {
        var extension = CertificatePolicyExtension.Build($"{PolicyA};{PolicyB}")!;

        extension.Oid!.Value.ShouldBe("2.5.29.32");
        extension.Critical.ShouldBeFalse();

        var parsed = BcCertificatePolicies.GetInstance(Asn1Object.FromByteArray(extension.RawData));
        parsed.GetPolicyInformation().Select(p => p.PolicyIdentifier.Id).ShouldBe([PolicyA, PolicyB]);
        parsed.GetPolicyInformation().ShouldAllBe(p => p.PolicyQualifiers == null);

        CertificatePolicyExtension.Build(PolicyA, critical: true)!.Critical.ShouldBeTrue();
    }

    [Fact]
    public void Decode_ReadsQualifiers_AndDescribeListsThem()
    {
        var cps = new BcPolicyQualifierInfo("https://example.com/cps");
        var policies = new BcCertificatePolicies(
        [
            new BcPolicyInformation(new DerObjectIdentifier(PolicyA), new DerSequence(cps)),
            new BcPolicyInformation(new DerObjectIdentifier(CertificatePolicyExtension.AnyPolicyOid)),
        ]);
        var extension = new X509Extension(CertificatePolicyExtension.CertificatePoliciesOid, policies.GetDerEncoded(), false);

        var decoded = CertificatePolicyExtension.Decode(extension);
        decoded.Select(p => p.PolicyOid).ShouldBe([PolicyA, CertificatePolicyExtension.AnyPolicyOid]);
        decoded[0].Qualifiers.ShouldBe(["CPS: https://example.com/cps"]);

        var text = CertificatePolicyExtension.Describe(extension);
        text.ShouldContain(PolicyA);
        text.ShouldContain("CPS: https://example.com/cps");
        text.ShouldContain("2.5.29.32.0 (anyPolicy)");
    }

    [Fact]
    public void Describe_UndecodableExtension_FallsBackToHex()
    {
        var extension = new X509Extension(CertificatePolicyExtension.CertificatePoliciesOid, [0x04, 0x01, 0x00], false);
        CertificatePolicyExtension.Describe(extension).ShouldBe("040100");
    }

    [Fact]
    public async Task ProfileService_Save_NormalizesPolicies_AndRefusesInvalidOnes()
    {
        var service = new CertificateProfileService(new TestDbContextFactory(), TestOperators.Full,
            NullLogger<CertificateProfileService>.Instance);

        var saved = await service.SaveAsync(new CertificateProfile
        {
            Name = "Policies",
            CertificateType = CertificateType.EndEntityClient,
            CertificatePolicyOids = $" {PolicyA}, {PolicyB} ",
        });
        saved.CertificatePolicyOids.ShouldBe($"{PolicyA};{PolicyB}");

        var ex = await Should.ThrowAsync<ArgumentException>(() => service.SaveAsync(new CertificateProfile
        {
            Name = "Bad policies",
            CertificateType = CertificateType.EndEntityClient,
            CertificatePolicyOids = "policy-one",
        }));
        ex.Message.ShouldContain("policy-one");
    }

    [Fact]
    public void Read_CertificateWithoutPolicies_ReturnsEmpty()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=No policies", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        CertificatePolicyExtension.Read(cert).ShouldBeEmpty();
    }
}
