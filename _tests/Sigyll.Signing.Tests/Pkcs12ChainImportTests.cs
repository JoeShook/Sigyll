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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>Importing a PKCS #12 file that carries its issuing CA certificates brings those in too.</summary>
public class Pkcs12ChainImportTests
{
    private const string Password = "test";

    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();
    private readonly CertificateParsingService _parser = new();

    private CertificateImportService CreateService() =>
        new(_dbFactory, TestOperators.Full, NullLogger<CertificateImportService>.Instance);

    [Fact]
    public async Task ChainInTheFile_IsImportedAsCaCertificates_AndTheCertificateHangsOffItsIssuer()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        using var chain = new TestChain();
        // Leaf first, then intermediate before root: the order in the file must not matter.
        var file = chain.Pkcs12(chain.Leaf, chain.Intermediate, chain.Root);

        var result = await CreateService().ImportParsedCertificateAsync(
            _parser.Parse(file, "client-chain.p12", Password)!, trustDomainId, password: Password);

        result.Success.ShouldBeTrue(result.Error);
        await using var db = _dbFactory.CreateDbContext();
        var cas = await db.CaCertificates.Where(c => c.TrustDomainId == trustDomainId).ToListAsync();
        cas.Count.ShouldBe(2);
        var root = cas.Single(c => c.Thumbprint == chain.Root.Thumbprint);
        var intermediate = cas.Single(c => c.Thumbprint == chain.Intermediate.Thumbprint);
        root.Name.ShouldBe("Chain Test Root");
        root.ParentId.ShouldBeNull();
        root.EncryptedPfxBytes.ShouldBeNull();
        intermediate.Name.ShouldBe("Chain Test Intermediate");
        intermediate.ParentId.ShouldBe(root.Id);
        intermediate.EncryptedPfxBytes.ShouldBeNull();

        var issued = await db.IssuedCertificates.SingleAsync();
        issued.Name.ShouldBe("client-chain");
        issued.IssuingCaCertificateId.ShouldBe(intermediate.Id);
        issued.EncryptedPfxBytes.ShouldBe(file);
        issued.PfxPassword.ShouldBe(Password);
    }

    [Fact]
    public async Task FileWithoutChain_FindsTheIssuer_AnEarlierFileBroughtIn()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        using var chain = new TestChain();
        var service = CreateService();
        await service.ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(chain.Leaf, chain.Intermediate, chain.Root), "first.p12", Password)!,
            trustDomainId, password: Password);

        using var second = chain.IssueLeaf("CN=Second Leaf");
        var result = await service.ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(second), "second.pfx", Password)!, trustDomainId, password: Password);

        result.Success.ShouldBeTrue(result.Error);
        await using var db = _dbFactory.CreateDbContext();
        var intermediateId = (await db.CaCertificates.SingleAsync(c => c.Thumbprint == chain.Intermediate.Thumbprint)).Id;
        (await db.IssuedCertificates.SingleAsync(c => c.Name == "second")).IssuingCaCertificateId.ShouldBe(intermediateId);
    }

    [Fact]
    public async Task CaCertificatesAlreadyInTheTrustDomain_AreNotImportedAgain()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        using var chain = new TestChain();
        var service = CreateService();
        await service.ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(chain.Leaf, chain.Intermediate, chain.Root), "first.p12", Password)!,
            trustDomainId, password: Password);

        using var second = chain.IssueLeaf("CN=Second Leaf");
        var result = await service.ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(second, chain.Root, chain.Intermediate), "second.p12", Password)!,
            trustDomainId, password: Password);

        result.Success.ShouldBeTrue(result.Error);
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.CountAsync(c => c.TrustDomainId == trustDomainId)).ShouldBe(2);
        (await db.IssuedCertificates.CountAsync()).ShouldBe(2);
    }

    [Fact]
    public async Task FileWithoutChain_AndNoIssuerInTheTrustDomain_StillAsksForTheCa()
    {
        var trustDomainId = await SeedTrustDomainAsync();
        using var chain = new TestChain();

        var result = await CreateService().ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(chain.Leaf), "alone.p12", Password)!, trustDomainId, password: Password);

        result.NeedsCaSelection.ShouldBeTrue();
    }

    [Fact]
    public async Task CertificateInAnotherTrustDomain_IsRefusedWithThatTrustDomainsName()
    {
        var first = await SeedTrustDomainAsync("First");
        var second = await SeedTrustDomainAsync("Second");
        using var chain = new TestChain();
        var file = chain.Pkcs12(chain.Leaf, chain.Intermediate, chain.Root);
        var service = CreateService();
        (await service.ImportParsedCertificateAsync(_parser.Parse(file, "client.p12", Password)!, first, password: Password))
            .Success.ShouldBeTrue();

        var result = await service.ImportParsedCertificateAsync(
            _parser.Parse(file, "client.p12", Password)!, second, password: Password);

        result.Success.ShouldBeFalse();
        result.NeedsCaSelection.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("trust domain 'First'");
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.CountAsync(c => c.TrustDomainId == second)).ShouldBe(0);
    }

    [Fact]
    public async Task NewCertificate_WhoseCaIsInAnotherTrustDomain_SaysWhereTheCaIs()
    {
        var first = await SeedTrustDomainAsync("First");
        var second = await SeedTrustDomainAsync("Second");
        using var chain = new TestChain();
        var service = CreateService();
        await service.ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(chain.Leaf, chain.Intermediate, chain.Root), "first.p12", Password)!,
            first, password: Password);

        using var other = chain.IssueLeaf("CN=Other Leaf");
        var result = await service.ImportParsedCertificateAsync(
            _parser.Parse(chain.Pkcs12(other, chain.Intermediate, chain.Root), "other.p12", Password)!,
            second, password: Password);

        result.Success.ShouldBeFalse();
        result.NeedsCaSelection.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("'Chain Test Intermediate' is already in trust domain 'First'");
    }

    private async Task<int> SeedTrustDomainAsync(string name = "Chain Import Test")
    {
        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = name, Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();
        return trustDomain.Id;
    }

    /// <summary>A root, an intermediate it issued, and a leaf the intermediate issued.</summary>
    private sealed class TestChain : IDisposable
    {
        private readonly RSA _intermediateKey = RSA.Create(2048);

        public X509Certificate2 Root { get; }
        public X509Certificate2 Intermediate { get; }
        public X509Certificate2 Leaf { get; }

        public TestChain()
        {
            using var rootKey = RSA.Create(2048);
            var rootRequest = new CertificateRequest("CN=Chain Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            using var rootWithKey = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
            Root = X509CertificateLoader.LoadCertificate(rootWithKey.RawData);

            var intermediateRequest = new CertificateRequest(
                "CN=Chain Test Intermediate", _intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
            intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(rootWithKey, true, false));
            Intermediate = intermediateRequest.Create(
                rootWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [1, 2, 3, 4]);

            Leaf = IssueLeaf("CN=Chain Test Leaf");
        }

        /// <summary>A leaf certificate from the intermediate, with its private key.</summary>
        public X509Certificate2 IssueLeaf(string subject)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using var issuer = Intermediate.CopyWithPrivateKey(_intermediateKey);
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            using var certificate = request.Create(
                issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), RandomNumberGenerator.GetBytes(8));
            return certificate.CopyWithPrivateKey(key);
        }

        /// <summary>A PKCS #12 file holding these certificates in this order.</summary>
        public byte[] Pkcs12(params X509Certificate2[] certificates)
        {
            var collection = new X509Certificate2Collection();
            collection.AddRange(certificates);
            return collection.Export(X509ContentType.Pkcs12, Password)!;
        }

        public void Dispose()
        {
            Root.Dispose();
            Intermediate.Dispose();
            Leaf.Dispose();
            _intermediateKey.Dispose();
        }
    }
}
