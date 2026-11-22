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
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Tefca;
using Sigyll.Common.ViewModels;
using Xunit;

namespace Sigyll.Signing.Tests;

public class TefcaConformanceTests
{
    private const string ClientUri = "https://client.example.org/fhir#T-TRTMNT";
    private const string Cdp = "http://crl.example.org/intermediate.crl";
    private const string Aia = "http://crl.example.org/intermediate.cer";

    // ---- the checker ----

    [Fact]
    public async Task ConformingProductionCertificate_PassesEveryCheck()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec());

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers);

        results.Where(r => r.Outcome != ConformanceOutcome.Pass)
            .ShouldAllBe(r => r.Name == "CDP/AIA reachable" && r.Outcome == ConformanceOutcome.Skipped);
        TefcaConformanceChecker.HasFailures(results).ShouldBeFalse();
        results.Select(r => r.Name).ShouldBeUnique();
        results.Count.ShouldBe(15);
    }

    [Fact]
    public async Task ValidationOu_SkipsPolicies()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Ou = "RCE-FHIR-TEST", Policies = [] });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers);

        Result(results, "Subject OU").Outcome.ShouldBe(ConformanceOutcome.Pass);
        Result(results, "DirectTrust certificate policies").Outcome.ShouldBe(ConformanceOutcome.Skipped);
        TefcaConformanceChecker.HasFailures(results).ShouldBeFalse();
    }

    [Fact]
    public async Task UnknownOu_Fails_AndPoliciesAreCheckedAsProduction()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Ou = "Engineering", Policies = [] });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers);

        Result(results, "Subject OU").Outcome.ShouldBe(ConformanceOutcome.Fail);
        Result(results, "DirectTrust certificate policies").Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Fact]
    public async Task ExplicitEnvironment_MustMatchOu()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Ou = "RCE-FHIR-TEST" });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { Environment = TefcaEnvironment.Production });

        Result(results, "Subject OU").Detail.ShouldContain("RCE-FHIR for production");
        Result(results, "Subject OU").Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Fact]
    public async Task MissingPolicy_IsNamed()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Policies = ["1.3.6.1.4.1.41179.0.2", "1.3.6.1.4.1.41179.1.5"] });

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), "DirectTrust certificate policies");

        result.Outcome.ShouldBe(ConformanceOutcome.Fail);
        result.Detail.ShouldBe("Missing 1.3.6.1.4.1.41179.3.1.");
    }

    [Fact]
    public async Task LeafIssuedDirectlyByRoot_FailsChain()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec(), byRoot: true);

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, [chain.Root]), "Chain root → intermediate → leaf");

        result.Outcome.ShouldBe(ConformanceOutcome.Fail);
        result.Detail.ShouldContain("found 2");
    }

    [Fact]
    public async Task ChainOutOfOrder_Fails()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec());

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, [chain.Root, chain.Intermediate]),
            "Chain root → intermediate → leaf");

        result.Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Fact]
    public async Task KeyUsage_MustBeDigitalSignatureOnly_AndCritical()
    {
        using var chain = TestChain.Create();
        using var extra = chain.IssueLeaf(new LeafSpec { KeyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment });
        using var notCritical = chain.IssueLeaf(new LeafSpec { KeyUsageCritical = false });

        Result(await TefcaConformanceChecker.CheckAsync(extra, chain.Issuers), "keyUsage digitalSignature only, critical")
            .Outcome.ShouldBe(ConformanceOutcome.Fail);
        Result(await TefcaConformanceChecker.CheckAsync(notCritical, chain.Issuers), "keyUsage digitalSignature only, critical")
            .Detail.ShouldContain("not critical");
    }

    [Fact]
    public async Task BasicConstraints_MustBeCritical_AndPresent()
    {
        using var chain = TestChain.Create();
        using var notCritical = chain.IssueLeaf(new LeafSpec { BasicConstraints = BasicConstraintsSpec.NotCritical });
        using var missing = chain.IssueLeaf(new LeafSpec { BasicConstraints = BasicConstraintsSpec.Missing });

        Result(await TefcaConformanceChecker.CheckAsync(notCritical, chain.Issuers), "basicConstraints cA=false, critical")
            .Outcome.ShouldBe(ConformanceOutcome.Fail);
        Result(await TefcaConformanceChecker.CheckAsync(missing, chain.Issuers), "basicConstraints cA=false, critical")
            .Detail.ShouldContain("missing");
    }

    [Fact]
    public async Task DnsNameSan_Fails()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { DnsName = "client.example.org" });

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), "No dNSName SANs");

        result.Outcome.ShouldBe(ConformanceOutcome.Fail);
        result.Detail.ShouldContain("client.example.org");
    }

    [Fact]
    public async Task CommonName_MustEqualASanUri_AndBeAtMost64Characters()
    {
        using var chain = TestChain.Create();
        using var mismatch = chain.IssueLeaf(new LeafSpec { Cn = "Example Client" });
        var longUri = "https://client.example.org/" + new string('a', 60) + "#T-TRTMNT";
        using var tooLong = chain.IssueLeaf(new LeafSpec { Cn = longUri, SanUri = longUri });

        Result(await TefcaConformanceChecker.CheckAsync(mismatch, chain.Issuers), "CN ≤ 64 characters and equal to a SAN URI")
            .Detail.ShouldContain("no SAN URI equals the CN");
        Result(await TefcaConformanceChecker.CheckAsync(tooLong, chain.Issuers), "CN ≤ 64 characters and equal to a SAN URI")
            .Detail.ShouldContain($"the CN is {longUri.Length} characters");
    }

    [Fact]
    public async Task CdpAndAia_MustBePresent_AndPlainHttp()
    {
        using var chain = TestChain.Create();
        using var https = chain.IssueLeaf(new LeafSpec { Cdp = "https://crl.example.org/i.crl" });
        using var noAia = chain.IssueLeaf(new LeafSpec { Aia = null });

        Result(await TefcaConformanceChecker.CheckAsync(https, chain.Issuers), "CRL distribution point uses http")
            .Outcome.ShouldBe(ConformanceOutcome.Fail);
        Result(await TefcaConformanceChecker.CheckAsync(noAia, chain.Issuers), "AIA caIssuers uses http")
            .Detail.ShouldContain("no AIA caIssuers URL");
    }

    [Fact]
    public async Task Reachability_UsesTheInjectedProbe()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec());
        var probe = new FakeProbe { Unreachable = { Aia } };

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { ReachabilityProbe = probe }), "CDP/AIA reachable");

        probe.Probed.ShouldBe([Cdp, Aia]);
        result.Outcome.ShouldBe(ConformanceOutcome.Fail);
        result.Detail.ShouldBe($"{Aia}: HTTP 404");

        probe.Unreachable.Clear();
        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { ReachabilityProbe = probe }), "CDP/AIA reachable")
            .Outcome.ShouldBe(ConformanceOutcome.Pass);
    }

    [Fact]
    public async Task SmallRsaKey_LongValidity_Fail()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { RsaKeySize = 1024, Validity = TimeSpan.FromDays(365 * 3 + 2) });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers);

        Result(results, "RSA key ≥ 2048 bits").Outcome.ShouldBe(ConformanceOutcome.Fail);
        Result(results, "Validity ≤ 3 years").Outcome.ShouldBe(ConformanceOutcome.Fail);
        Result(results, "Signature SHA-256 with RSA").Outcome.ShouldBe(ConformanceOutcome.Pass);
    }

    [Fact]
    public async Task EcKey_FailsKeyCheck()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { UseEcKey = true });

        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), "RSA key ≥ 2048 bits")
            .Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Fact]
    public async Task Sha384Signature_Fails()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Hash = HashAlgorithmName.SHA384 });

        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), "Signature SHA-256 with RSA")
            .Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    /// <summary>A placeholder: the query parameter name is configuration with no default.</summary>
    private const string Param = "configuredName";

    [Theory]
    [InlineData("https://client.example.org/fhir#T-TRTMNT")]
    [InlineData("https://client.example.org/fhir/T-IAS")]
    [InlineData("https://client.example.org/fhir?configuredName=T-PH-ECR")]
    [InlineData("urn:oid:2.999#T-TREAT")]
    public async Task SanFormat_AnyCandidateFormPasses_WhenTheQueryParameterIsConfigured(string sanUri)
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = sanUri, SanUri = sanUri });

        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
                new TefcaConformanceOptions { ExchangePurposeQueryParameter = Param }), TefcaSanFormatRule.CheckName)
            .Outcome.ShouldBe(ConformanceOutcome.Pass);
    }

    [Fact]
    public async Task SanFormat_QueryFormIsNotRecognized_WithoutAConfiguredName()
    {
        using var chain = TestChain.Create();
        const string uri = "https://client.example.org/fhir?configuredName=T-PH-ECR";
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = uri, SanUri = uri });

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), TefcaSanFormatRule.CheckName);

        result.Outcome.ShouldBe(ConformanceOutcome.Warning);
        result.Detail.ShouldContain("no query parameter is configured");
    }

    [Fact]
    public async Task SanFormat_ConflictingDuplicateParameters_AreAmbiguous()
    {
        using var chain = TestChain.Create();
        const string uri = "https://c.example/f?configuredName=T-TRTMNT&configuredName=T-IAS"; // CN stays within 64
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = uri, SanUri = uri });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { ExchangePurposeQueryParameter = Param });

        Result(results, TefcaSanFormatRule.CheckName).Outcome.ShouldBe(ConformanceOutcome.Warning);
        Result(results, TefcaSanFormatRule.CheckName).Detail.ShouldStartWith("Ambiguous");
        TefcaConformanceChecker.HasFailures(results).ShouldBeFalse();
    }

    [Fact]
    public async Task SanFormat_WithoutAnExchangePurpose_IsOnlyAWarning()
    {
        using var chain = TestChain.Create();
        const string plain = "https://client.example.org/fhir";
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = plain, SanUri = plain });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers);

        Result(results, TefcaSanFormatRule.CheckName).Outcome.ShouldBe(ConformanceOutcome.Warning);
        TefcaConformanceChecker.HasFailures(results).ShouldBeFalse();
    }

    [Fact]
    public async Task SanFormatRule_IsReplaceable()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec());
        var rule = new FixedRule();

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers, new TefcaConformanceOptions { SanFormatRule = rule });

        rule.Seen.ShouldBe([ClientUri]);
        results.ShouldContain(r => r.Name == "custom rule");
        results.ShouldNotContain(r => r.Name == TefcaSanFormatRule.CheckName);
    }

    [Theory]
    // fragment and last path segment: recognized with or without a configured name
    [InlineData("https://a.example/fhir#T-TRTMNT", null, "Found", "T-TRTMNT")]
    [InlineData("https://a.example/fhir/T-HCO-QAI", null, "Found", "T-HCO-QAI")]
    [InlineData("https://a.example/fhir#T-NOPE", Param, "NotFound", "")]
    [InlineData("https://a.example/fhir/", Param, "NotFound", "")]
    [InlineData("", Param, "NotFound", "")]
    // exact, case-sensitive XP match; nothing trimmed
    [InlineData("https://a.example/fhir#t-trtmnt", Param, "NotFound", "")]
    [InlineData("https://a.example/fhir#T-TRTMNT ", Param, "NotFound", "")]
    // no percent-decoding: %2D is not '-'
    [InlineData("https://a.example/fhir#T%2DIAS", Param, "NotFound", "")]
    [InlineData("https://a.example/fhir?configuredName=T%2DIAS", Param, "NotFound", "")]
    // query: only the configured name, compared ordinally; value verbatim
    [InlineData("https://a.example/fhir?foo=1&configuredName=T-PYMNT", Param, "Found", "T-PYMNT")]
    [InlineData("https://a.example/fhir?configuredName=T-PYMNT", null, "NotFound", "")]
    [InlineData("https://a.example/fhir?ConfiguredName=T-IAS", Param, "NotFound", "")]
    [InlineData("https://a.example/fhir?configuredName=T-IAS#frag", Param, "Found", "T-IAS")]
    // duplicates: identical values are fine, conflicting ones are ambiguous
    [InlineData("https://a.example/fhir?configuredName=T-IAS&configuredName=T-IAS", Param, "Found", "T-IAS")]
    [InlineData("https://a.example/fhir?configuredName=T-IAS&configuredName=T-PH", Param, "Ambiguous", "")]
    [InlineData("https://a.example/fhir?configuredName=T-IAS&configuredName=T-PH#T-IAS", Param, "Ambiguous", "")]
    public void ExchangePurpose_FromSanUri(string uri, string? parameter, string outcome, string code)
    {
        TefcaExchangePurpose.FromSanUri(uri, parameter, out var actual, out _).ToString().ShouldBe(outcome);
        actual.ShouldBe(code);
    }

    [Fact]
    public async Task CommonName_ComparesOrdinally()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = "https://Client.example.org/fhir#T-TRTMNT" });

        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), "CN ≤ 64 characters and equal to a SAN URI")
            .Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Theory]
    [InlineData(TefcaCertificateRole.Server, ConformanceOutcome.Fail)]
    [InlineData(TefcaCertificateRole.Unknown, ConformanceOutcome.Warning)]
    [InlineData(TefcaCertificateRole.Client, ConformanceOutcome.Skipped)]
    public async Task ServerSanUri_WithTrailingSlash(TefcaCertificateRole role, ConformanceOutcome expected)
    {
        using var chain = TestChain.Create();
        const string baseUrl = "https://fhir.example.org/r4/";
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = baseUrl, SanUri = baseUrl });

        var result = Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { Role = role }), TefcaConformanceChecker.TrailingSlashCheckName);

        result.Outcome.ShouldBe(expected);
        if (expected != ConformanceOutcome.Skipped)
            result.Detail.ShouldContain("SSRAA 3.0.0");
    }

    [Fact]
    public async Task ServerSanUri_WithoutTrailingSlash_Passes()
    {
        using var chain = TestChain.Create();
        const string baseUrl = "https://fhir.example.org/r4";
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = baseUrl, SanUri = baseUrl });

        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
                new TefcaConformanceOptions { Role = TefcaCertificateRole.Server }), TefcaConformanceChecker.TrailingSlashCheckName)
            .Outcome.ShouldBe(ConformanceOutcome.Pass);
    }

    [Fact]
    public async Task ServerCertificate_SkipsTheSanFormat_AndPassesEveryOtherCheck()
    {
        using var chain = TestChain.Create();
        const string baseUrl = "https://fhir.example.org/r4";
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = baseUrl, SanUri = baseUrl });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { Role = TefcaCertificateRole.Server, SanFormatRule = new FixedRule() });

        Result(results, TefcaSanFormatRule.CheckName).Outcome.ShouldBe(ConformanceOutcome.Skipped);
        Result(results, TefcaSanFormatRule.CheckName).Detail.ShouldContain("FHIR base URLs");
        results.ShouldNotContain(r => r.Name == "custom rule");
        Result(results, "CN ≤ 64 characters and equal to a SAN URI").Outcome.ShouldBe(ConformanceOutcome.Pass);
        results.Where(r => r.Outcome != ConformanceOutcome.Pass).Select(r => r.Name)
            .ShouldBe([TefcaSanFormatRule.CheckName, "CDP/AIA reachable"], ignoreOrder: true);
    }

    [Fact]
    public async Task ServerCertificate_CnMustEqualTheBaseUrlSan()
    {
        using var chain = TestChain.Create();
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = "https://fhir.example.org/R4", SanUri = "https://fhir.example.org/r4" });

        var results = await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers,
            new TefcaConformanceOptions { Role = TefcaCertificateRole.Server });

        Result(results, "CN ≤ 64 characters and equal to a SAN URI").Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Fact]
    public async Task UnknownRole_KeepsTheSanFormatWarning()
    {
        using var chain = TestChain.Create();
        const string baseUrl = "https://fhir.example.org/r4";
        using var leaf = chain.IssueLeaf(new LeafSpec { Cn = baseUrl, SanUri = baseUrl });

        Result(await TefcaConformanceChecker.CheckAsync(leaf, chain.Issuers), TefcaSanFormatRule.CheckName)
            .Outcome.ShouldBe(ConformanceOutcome.Warning);
    }

    // ---- issuance hook and the stored-certificate service ----

    [Theory]
    [InlineData("TEFCA FHIR Client", true)]
    [InlineData("my tefca profile", true)]
    [InlineData("UDAP Client", false)]
    public void IsTefcaProfile_ByName(string name, bool expected) =>
        TefcaConformanceService.IsTefcaProfile(new CertificateProfile { Name = name }).ShouldBe(expected);

    [Fact]
    public async Task IssuanceFromTefcaProfile_AttachesTheCheck()
    {
        var factory = new TestDbContextFactory();
        var seed = await SeedAsync(factory, "TEFCA FHIR Client");

        var result = await IssueAsync(factory, seed);

        result.Success.ShouldBeTrue(result.Error);
        result.ConformanceResults.ShouldNotBeNull();
        Result(result.ConformanceResults, "Subject OU").Outcome.ShouldBe(ConformanceOutcome.Pass);
        Result(result.ConformanceResults, "Chain root → intermediate → leaf").Outcome.ShouldBe(ConformanceOutcome.Pass);
        Result(result.ConformanceResults, "CDP/AIA reachable").Outcome.ShouldBe(ConformanceOutcome.Skipped);
    }

    [Fact]
    public async Task IssuanceFromOtherProfile_DoesNotCheck()
    {
        var factory = new TestDbContextFactory();
        var seed = await SeedAsync(factory, "UDAP Client");

        var result = await IssueAsync(factory, seed);

        result.Success.ShouldBeTrue(result.Error);
        result.ConformanceResults.ShouldBeNull();
    }

    [Fact]
    public async Task Service_ChecksAStoredCertificate_AndProbesOnlyWhenAsked()
    {
        var factory = new TestDbContextFactory();
        var seed = await SeedAsync(factory, "UDAP Client");
        var issued = await IssueAsync(factory, seed);
        var probe = new FakeProbe();
        var service = new TefcaConformanceService(factory, TestOperators.Full, probe);

        var offline = await service.CheckIssuedCertificateAsync(issued.EntityId!.Value);
        probe.Probed.ShouldBeEmpty();
        Result(offline!, "CDP/AIA reachable").Outcome.ShouldBe(ConformanceOutcome.Skipped);

        var online = await service.CheckIssuedCertificateAsync(issued.EntityId!.Value, probeReachability: true);
        probe.Probed.ShouldNotBeEmpty();
        Result(online!, "CDP/AIA reachable").Outcome.ShouldBe(ConformanceOutcome.Pass);

        (await service.CheckIssuedCertificateAsync(int.MaxValue)).ShouldBeNull();
    }

    [Fact]
    public async Task IssuanceFromTefcaServerProfile_FailsATrailingSlashBaseUrl()
    {
        var factory = new TestDbContextFactory();
        var seed = await SeedAsync(factory, "TEFCA FHIR Server", CertificateType.EndEntityServer);

        var result = await IssueAsync(factory, seed, "https://fhir.example.org/r4/");

        result.Success.ShouldBeTrue(result.Error);
        Result(result.ConformanceResults!, TefcaConformanceChecker.TrailingSlashCheckName).Outcome.ShouldBe(ConformanceOutcome.Fail);
    }

    [Fact]
    public async Task Service_UsesTheConfiguredQueryParameter()
    {
        var factory = new TestDbContextFactory();
        var seed = await SeedAsync(factory, "UDAP Client");
        var issued = await IssueAsync(factory, seed, "https://client.example.org/fhir?configuredName=T-IAS");
        var settings = Microsoft.Extensions.Options.Options.Create(new TefcaConformanceSettings { ExchangePurposeQueryParameter = Param });

        var unconfigured = await new TefcaConformanceService(factory, TestOperators.Full).CheckIssuedCertificateAsync(issued.EntityId!.Value);
        var configured = await new TefcaConformanceService(factory, TestOperators.Full, settings: settings).CheckIssuedCertificateAsync(issued.EntityId!.Value);

        Result(unconfigured!, TefcaSanFormatRule.CheckName).Outcome.ShouldBe(ConformanceOutcome.Warning);
        Result(configured!, TefcaSanFormatRule.CheckName).Outcome.ShouldBe(ConformanceOutcome.Pass);
        Result(configured!, TefcaConformanceChecker.TrailingSlashCheckName).Outcome.ShouldBe(ConformanceOutcome.Skipped);
    }

    private static ConformanceCheckResult Result(IEnumerable<ConformanceCheckResult> results, string name) =>
        results.Single(r => r.Name == name);

    private static Task<CsrIssuanceResult> IssueAsync(TestDbContextFactory factory,
        (int IntermediateId, int ProfileId, int TrustDomainId) seed, string sanUri = ClientUri)
    {
        using var key = RSA.Create(2048);
        var csr = new CertificateRequest($"CN={sanUri}, OU=RCE-FHIR, O=Example", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1).CreateSigningRequestPem();
        var service = new CertificateIssuanceService(factory, TestOperators.Full, NullLogger<CertificateIssuanceService>.Instance);
        return service.IssueCertificateFromCsrAsync(new CsrIssuanceRequest
        {
            IssuingCaCertificateId = seed.IntermediateId,
            ProfileId = seed.ProfileId,
            TrustDomainId = seed.TrustDomainId,
            CsrPem = csr,
            SubjectAltNames = [new SanEntry(SanType.Uri, sanUri)],
            CdpUrls = [Cdp],
            AiaUrls = [Aia],
        });
    }

    private static async Task<(int IntermediateId, int ProfileId, int TrustDomainId)> SeedAsync(
        TestDbContextFactory factory, string profileName, CertificateType type = CertificateType.EndEntityClient)
    {
        await using var db = factory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "TEFCA", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        var profile = new CertificateProfile
        {
            Name = profileName,
            CertificateType = type,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            IsKeyUsageCritical = true,
            IsBasicConstraintsCritical = true,
            CertificatePolicyOids = string.Join(";", TefcaConformanceChecker.ProductionPolicyOids),
            IncludeCdp = true,
            CdpUrlTemplate = Cdp,
            IncludeAia = true,
            AiaUrlTemplate = Aia,
            SubjectAltNameTypes = "URI",
        };
        db.CertificateProfiles.Add(profile);
        await db.SaveChangesAsync();

        using var chain = TestChain.Create();
        var root = Entity(chain.Root, trustDomain.Id, null, withKey: false);
        db.CaCertificates.Add(root);
        await db.SaveChangesAsync();
        var intermediate = Entity(chain.Intermediate, trustDomain.Id, root.Id, withKey: true);
        db.CaCertificates.Add(intermediate);
        await db.SaveChangesAsync();

        return (intermediate.Id, profile.Id, trustDomain.Id);
    }

    private static CaCertificate Entity(X509Certificate2 cert, int trustDomainId, int? parentId, bool withKey) => new()
    {
        TrustDomainId = trustDomainId,
        ParentId = parentId,
        Name = cert.GetNameInfo(X509NameType.SimpleName, false),
        Subject = cert.Subject,
        X509CertificatePem = cert.ExportCertificatePem(),
        EncryptedPfxBytes = withKey ? cert.Export(X509ContentType.Pkcs12, "test") : null,
        PfxPassword = withKey ? "test" : null,
        Thumbprint = cert.Thumbprint,
        SerialNumber = cert.SerialNumber,
        KeyAlgorithm = "RSA",
        KeySize = 2048,
        NotBefore = cert.NotBefore.ToUniversalTime(),
        NotAfter = cert.NotAfter.ToUniversalTime(),
    };

    // ---- test chain ----

    private enum BasicConstraintsSpec { Critical, NotCritical, Missing }

    private sealed record LeafSpec
    {
        public string Ou { get; init; } = "RCE-FHIR";
        public string? Cn { get; init; } = ClientUri;
        public string SanUri { get; init; } = ClientUri;
        public string? DnsName { get; init; }
        public X509KeyUsageFlags KeyUsage { get; init; } = X509KeyUsageFlags.DigitalSignature;
        public bool KeyUsageCritical { get; init; } = true;
        public BasicConstraintsSpec BasicConstraints { get; init; } = BasicConstraintsSpec.Critical;
        public IReadOnlyList<string> Policies { get; init; } = TefcaConformanceChecker.ProductionPolicyOids;
        public string? Cdp { get; init; } = TefcaConformanceTests.Cdp;
        public string? Aia { get; init; } = TefcaConformanceTests.Aia;
        public int RsaKeySize { get; init; } = 2048;
        public bool UseEcKey { get; init; }
        public HashAlgorithmName Hash { get; init; } = HashAlgorithmName.SHA256;
        public TimeSpan Validity { get; init; } = TimeSpan.FromDays(365);
    }

    private sealed class TestChain : IDisposable
    {
        public required X509Certificate2 Root { get; init; }
        public required X509Certificate2 Intermediate { get; init; }
        public IReadOnlyList<X509Certificate2> Issuers => [Intermediate, Root];

        public static TestChain Create()
        {
            using var rootKey = RSA.Create(2048);
            var rootReq = new CertificateRequest("CN=Test TEFCA Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(10));

            using var intKey = RSA.Create(2048);
            var intReq = new CertificateRequest("CN=Test TEFCA Intermediate", intKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            intReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            intReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var intPublic = intReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(8), RandomNumberGenerator.GetBytes(16));
            var intermediate = intPublic.CopyWithPrivateKey(intKey);

            return new TestChain { Root = root, Intermediate = intermediate };
        }

        public X509Certificate2 IssueLeaf(LeafSpec spec, bool byRoot = false)
        {
            var subject = spec.Cn == null ? $"OU={spec.Ou}, O=Example" : $"CN={spec.Cn}, OU={spec.Ou}, O=Example";
            using var rsa = spec.UseEcKey ? null : RSA.Create(spec.RsaKeySize);
            using var ec = spec.UseEcKey ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
            var req = rsa != null
                ? new CertificateRequest(subject, rsa, spec.Hash, RSASignaturePadding.Pkcs1)
                : new CertificateRequest(subject, ec!, spec.Hash);

            req.CertificateExtensions.Add(new X509KeyUsageExtension(spec.KeyUsage, spec.KeyUsageCritical));
            if (spec.BasicConstraints != BasicConstraintsSpec.Missing)
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, spec.BasicConstraints == BasicConstraintsSpec.Critical));

            // Written verbatim (SubjectAlternativeNameBuilder would canonicalize the URI)
            List<SanEntry> sans = [new SanEntry(SanType.Uri, spec.SanUri)];
            if (spec.DnsName != null) sans.Add(new SanEntry(SanType.Dns, spec.DnsName));
            req.CertificateExtensions.Add(SanExtensionBuilder.Build(sans)!);

            if (CertificatePolicyExtension.Build(spec.Policies) is { } policies)
                req.CertificateExtensions.Add(policies);
            if (spec.Cdp != null)
                req.CertificateExtensions.Add(CertificateExtensionHelpers.MakeCdp(spec.Cdp));
            if (spec.Aia != null)
                req.CertificateExtensions.Add(CertificateExtensionHelpers.BuildAiaExtension(new Uri(spec.Aia)));

            var issuer = byRoot ? Root : Intermediate;
            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            var generator = X509SignatureGenerator.CreateForRSA(issuer.GetRSAPrivateKey()!, RSASignaturePadding.Pkcs1);
            return req.Create(issuer.SubjectName, generator, notBefore, notBefore + spec.Validity, RandomNumberGenerator.GetBytes(16));
        }

        public void Dispose()
        {
            Root.Dispose();
            Intermediate.Dispose();
        }
    }

    private sealed class FakeProbe : IUrlReachabilityProbe
    {
        public HashSet<string> Unreachable { get; } = [];
        public List<string> Probed { get; } = [];

        public Task<string?> ProbeAsync(Uri url, CancellationToken cancellationToken = default)
        {
            Probed.Add(url.OriginalString);
            return Task.FromResult(Unreachable.Contains(url.OriginalString) ? "HTTP 404" : null);
        }
    }

    private sealed class FixedRule : ITefcaSanFormatRule
    {
        public List<string> Seen { get; } = [];

        public ConformanceCheckResult Evaluate(IReadOnlyList<string> sanUris)
        {
            Seen.AddRange(sanUris);
            return ConformanceCheckResult.Warning("custom rule", "evaluated");
        }
    }
}
