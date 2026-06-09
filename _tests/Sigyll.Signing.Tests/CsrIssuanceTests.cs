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
using Sigyll.Common.ViewModels;
using Xunit;

namespace Sigyll.Signing.Tests;

public class CsrIssuanceTests
{
    private readonly TestDbContextFactory _dbFactory = new();

    private CertificateIssuanceService CreateService() =>
        new(_dbFactory, NullLogger<CertificateIssuanceService>.Instance);

    [Fact]
    public async Task IssueFromCsr_UsesCsrPublicKey_AndStoresNoPrivateKey()
    {
        var (caId, templateId, trustDomainId) = await SeedAsync();
        using var subjectKey = RSA.Create(2048);
        var csrPem = BuildCsrPem(subjectKey, "CN=api.example.com");

        var result = await CreateService().IssueCertificateFromCsrAsync(new CsrIssuanceRequest
        {
            IssuingCaCertificateId = caId,
            TemplateId = templateId,
            TrustDomainId = trustDomainId,
            CsrPem = csrPem,
            SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com")],
        });

        result.Success.ShouldBeTrue(result.Error);
        result.CertificatePem.ShouldNotBeNullOrEmpty();
        result.ChainPem.ShouldNotBeNullOrEmpty();

        using var issued = X509Certificate2.CreateFromPem(result.CertificatePem);
        using var issuedKey = issued.GetRSAPublicKey()!;
        // The issued cert must carry the public key from the CSR (the requester holds the private key).
        Convert.ToBase64String(issuedKey.ExportSubjectPublicKeyInfo())
            .ShouldBe(Convert.ToBase64String(subjectKey.ExportSubjectPublicKeyInfo()));

        // No private key is persisted for portal-issued certs.
        await using var db = _dbFactory.CreateDbContext();
        var entity = await db.IssuedCertificates.FindAsync(result.EntityId);
        entity!.EncryptedPfxBytes.ShouldBeNull();
    }

    [Fact]
    public async Task IssueFromCsr_AppliesTemplateEku()
    {
        var (caId, templateId, trustDomainId) = await SeedAsync();
        using var subjectKey = RSA.Create(2048);
        var csrPem = BuildCsrPem(subjectKey, "CN=eku.example.com");

        var result = await CreateService().IssueCertificateFromCsrAsync(new CsrIssuanceRequest
        {
            IssuingCaCertificateId = caId,
            TemplateId = templateId,
            TrustDomainId = trustDomainId,
            CsrPem = csrPem,
            SubjectAltNames = [new SanEntry(SanType.Dns, "eku.example.com")],
        });

        result.Success.ShouldBeTrue(result.Error);
        using var issued = X509Certificate2.CreateFromPem(result.CertificatePem!);
        var eku = issued.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        eku.ShouldNotBeNull();
        eku!.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value)
            .ShouldContain("1.3.6.1.5.5.7.3.1"); // serverAuth
    }

    [Fact]
    public async Task IssueFromCsr_RejectsCaTemplate()
    {
        var (caId, _, trustDomainId) = await SeedAsync();
        await using var db = _dbFactory.CreateDbContext();
        var caTemplate = new CertificateTemplate
        {
            Name = "Root CA", CertificateType = CertificateType.RootCa, KeyAlgorithm = "RSA", KeySize = 4096,
        };
        db.CertificateTemplates.Add(caTemplate);
        await db.SaveChangesAsync();

        using var subjectKey = RSA.Create(2048);
        var result = await CreateService().IssueCertificateFromCsrAsync(new CsrIssuanceRequest
        {
            IssuingCaCertificateId = caId,
            TemplateId = caTemplate.Id,
            TrustDomainId = trustDomainId,
            CsrPem = BuildCsrPem(subjectKey, "CN=nope"),
        });

        result.Success.ShouldBeFalse();
        result.Error.ShouldContain("end-entity");
    }

    private static string BuildCsrPem(RSA key, string subjectDn)
    {
        var req = new CertificateRequest(subjectDn, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSigningRequestPem();
    }

    private async Task<(int caId, int templateId, int trustDomainId)> SeedAsync()
    {
        await using var db = _dbFactory.CreateDbContext();

        var trustDomain = new TrustDomain { Name = "Test TD", Enabled = true };
        db.TrustDomains.Add(trustDomain);

        var template = new CertificateTemplate
        {
            Name = "SSL Server",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            IsKeyUsageCritical = true,
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            HashAlgorithm = "SHA256",
            AllowAutoIssue = true,
        };
        db.CertificateTemplates.Add(template);

        // Self-signed issuing CA with a local private key (PFX).
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test Issuing CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Test Issuing CA",
            Subject = "CN=Test Issuing CA",
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
        return (ca.Id, template.Id, trustDomain.Id);
    }
}
