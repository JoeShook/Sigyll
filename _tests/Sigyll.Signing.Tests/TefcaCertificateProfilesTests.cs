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
using Sigyll.Common.Validators;
using Sigyll.Common.ViewModels;
using Xunit;

namespace Sigyll.Signing.Tests;

public class TefcaCertificateProfilesTests
{
    private readonly TestDbContextFactory _dbFactory = new();

    private static CertificateProfile Preset(string name) =>
        TefcaCertificateProfiles.All().Single(p => p.Name == name);

    [Fact]
    public void All_FivePresets_WithUniqueNames()
    {
        var names = TefcaCertificateProfiles.All().Select(p => p.Name).ToList();
        names.ShouldBe(
        [
            TefcaCertificateProfiles.IntermediateName,
            TefcaCertificateProfiles.ClientName,
            TefcaCertificateProfiles.ServerName,
            TefcaCertificateProfiles.ValidationClientName,
            TefcaCertificateProfiles.ValidationServerName,
        ]);
        TefcaCertificateProfiles.All().ShouldAllBe(p => p.IsPreset);
    }

    [Fact]
    public void Intermediate_PathLengthZero_WithCdpAndAia()
    {
        var p = Preset(TefcaCertificateProfiles.IntermediateName);
        p.CertificateType.ShouldBe(CertificateType.IntermediateCa);
        p.IsBasicConstraintsCa.ShouldBeTrue();
        p.IsBasicConstraintsCritical.ShouldBeTrue();
        p.PathLengthConstraint.ShouldBe(0);
        p.KeyUsageFlags.ShouldBe((int)(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign));
        p.IncludeCdp.ShouldBeTrue();
        p.IncludeAia.ShouldBeTrue();
        p.HashAlgorithm.ShouldBe("SHA256");
    }

    [Theory]
    [InlineData(TefcaCertificateProfiles.ClientName, CertificateType.EndEntityClient, "RCE-FHIR", true)]
    [InlineData(TefcaCertificateProfiles.ServerName, CertificateType.EndEntityServer, "RCE-FHIR", true)]
    [InlineData(TefcaCertificateProfiles.ValidationClientName, CertificateType.EndEntityClient, "RCE-FHIR-TEST", false)]
    [InlineData(TefcaCertificateProfiles.ValidationServerName, CertificateType.EndEntityServer, "RCE-FHIR-TEST", false)]
    public void Leaf_FollowsTheTefcaProfile(string name, CertificateType type, string ou, bool policies)
    {
        var p = Preset(name);
        p.CertificateType.ShouldBe(type);
        p.KeyAlgorithm.ShouldBe("RSA");
        p.KeySize.ShouldBeGreaterThanOrEqualTo(2048);
        p.HashAlgorithm.ShouldBe("SHA256");
        p.ValidityDays.ShouldBeLessThanOrEqualTo(3 * 365);
        p.KeyUsageFlags.ShouldBe((int)X509KeyUsageFlags.DigitalSignature);
        p.IsKeyUsageCritical.ShouldBeTrue();
        p.IsBasicConstraintsCa.ShouldBeFalse();
        p.IsBasicConstraintsCritical.ShouldBeTrue();
        p.ExtendedKeyUsageOids.ShouldBeNull();
        IssuanceValidator.ParseSanTypes(p.SubjectAltNameTypes).ShouldBe([SanType.Uri]);
        p.SubjectTemplate.ShouldContain($"OU={ou},");
        p.SubjectTemplate.ShouldContain("C=US");
        p.RequiresRaApproval.ShouldBeTrue();
        p.AllowAutoIssue.ShouldBeFalse();

        if (policies)
            CertificatePolicyExtension.Parse(p.CertificatePolicyOids).ShouldBe(
                ["1.3.6.1.4.1.41179.0.2", "1.3.6.1.4.1.41179.1.5", "1.3.6.1.4.1.41179.3.1"]);
        else
            p.CertificatePolicyOids.ShouldBeNull();
    }

    [Theory]
    [InlineData(TefcaCertificateProfiles.ClientName, "RCE-FHIR", true)]
    [InlineData(TefcaCertificateProfiles.ServerName, "RCE-FHIR", true)]
    [InlineData(TefcaCertificateProfiles.ValidationClientName, "RCE-FHIR-TEST", false)]
    public async Task IssueFromCsr_WithLeafPreset_WritesTheTefcaExtensions(string name, string ou, bool policies)
    {
        var (caId, profileId, trustDomainId) = await SeedAsync(Preset(name));
        const string uri = "https://fhir.example.org/r4";

        using var subjectKey = RSA.Create(2048);
        var subject = $"CN={uri}, OU={ou}, O=Example Health, ST=CA, C=US";
        var csr = new CertificateRequest(subject, subjectKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequestPem();

        var result = await new CertificateIssuanceService(_dbFactory, TestOperators.Full,
                NullLogger<CertificateIssuanceService>.Instance)
            .IssueCertificateFromCsrAsync(new CsrIssuanceRequest
            {
                IssuingCaCertificateId = caId,
                ProfileId = profileId,
                TrustDomainId = trustDomainId,
                CsrPem = csr,
                SubjectAltNames = [new SanEntry(SanType.Uri, uri), new SanEntry(SanType.Npi, "1234567893")],
                CdpUrls = ["http://crl.example.org/tefca.crl"],
                AiaUrls = ["http://crl.example.org/tefca.cer"],
            });

        result.Success.ShouldBeTrue(result.Error);
        using var issued = X509Certificate2.CreateFromPem(result.CertificatePem!);

        var ku = issued.Extensions.OfType<X509KeyUsageExtension>().Single();
        ku.Critical.ShouldBeTrue();
        ku.KeyUsages.ShouldBe(X509KeyUsageFlags.DigitalSignature);

        var bc = issued.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        bc.Critical.ShouldBeTrue();
        bc.CertificateAuthority.ShouldBeFalse();

        issued.Extensions.OfType<X509EnhancedKeyUsageExtension>().ShouldBeEmpty();
        issued.SignatureAlgorithm.Value.ShouldBe("1.2.840.113549.1.1.11"); // sha256WithRSAEncryption
        CsrGenerationService.ExtractSubjectAltNames(issued).ShouldBe(
            [new SanEntry(SanType.Uri, uri), new SanEntry(SanType.Npi, "1234567893")]);

        var issuedPolicies = CertificatePolicyExtension.Read(issued);
        if (policies)
            issuedPolicies.ShouldBe(CertificatePolicyExtension.Parse(TefcaCertificateProfiles.ProductionPolicyOids));
        else
            issuedPolicies.ShouldBeEmpty();
    }

    [Fact]
    public async Task IssueFromCsr_WithLeafPreset_WithoutUriSan_IsRejected()
    {
        var (caId, profileId, trustDomainId) = await SeedAsync(Preset(TefcaCertificateProfiles.ClientName));

        using var subjectKey = RSA.Create(2048);
        var csr = new CertificateRequest("CN=no-uri", subjectKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSigningRequestPem();

        var result = await new CertificateIssuanceService(_dbFactory, TestOperators.Full,
                NullLogger<CertificateIssuanceService>.Instance)
            .IssueCertificateFromCsrAsync(new CsrIssuanceRequest
            {
                IssuingCaCertificateId = caId,
                ProfileId = profileId,
                TrustDomainId = trustDomainId,
                CsrPem = csr,
                SubjectAltNames = [new SanEntry(SanType.Npi, "1234567893")],
            });

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("URI");
    }

    private async Task<(int caId, int profileId, int trustDomainId)> SeedAsync(CertificateProfile profile)
    {
        await using var db = _dbFactory.CreateDbContext();

        var trustDomain = new TrustDomain { Name = "TEFCA TD", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        db.CertificateProfiles.Add(profile);

        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=TEFCA Test Intermediate", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "TEFCA Test Intermediate",
            Subject = "CN=TEFCA Test Intermediate",
            X509CertificatePem = caCert.ExportCertificatePem(),
            EncryptedPfxBytes = caCert.Export(X509ContentType.Pkcs12, "test"),
            PfxPassword = "test",
            Thumbprint = caCert.Thumbprint,
            SerialNumber = caCert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = caCert.NotBefore,
            NotAfter = caCert.NotAfter,
        };
        db.CaCertificates.Add(ca);

        await db.SaveChangesAsync();
        return (ca.Id, profile.Id, trustDomain.Id);
    }
}
