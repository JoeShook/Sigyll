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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services.Jobs;
using Sigyll.Common.Services.Signing;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace Sigyll.Signing.Tests;

/// <summary>
/// Covers the "imported sub-CA" scenario: a CA certificate issued by an external CA that is
/// NOT in the database, imported with its private key. The operator must produce CRLs signed
/// by that certificate and hand them to the external CA. The CRL must therefore be built from
/// the selected certificate itself — issuer DN and AKI must match the certificate as issued.
/// </summary>
public class CrlGenerationServiceTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();
    private readonly CrlGenerationService _service;

    // An SKI that is deliberately NOT SHA-1(publicKey) — mimics an external CA that assigns
    // key identifiers by some other method. The CRL's AKI must still equal this value.
    private static readonly byte[] ExternalSki = Convert.FromHexString("0102030405060708090A0B0C0D0E0F1011121314");

    public CrlGenerationServiceTests()
    {
        _service = new CrlGenerationService(
            _dbFactory, TestOperators.Full,
            NullLogger<CrlGenerationService>.Instance,
            new LocalSigningProvider());
    }

    [Fact]
    public async Task GenerateCrlAsync_ImportedSubCaWithExternalIssuer_ProducesCrlBuiltFromThatCertificate()
    {
        var (caId, subCaCert) = await SeedImportedSubCaAsync("RSA");

        var result = await _service.GenerateCrlAsync(caId);

        result.IsSuccess.ShouldBeTrue(result.Error);
        result.CrlNumber.ShouldBe(1);
        result.RevokedCount.ShouldBe(0);

        var crl = await LoadLatestCrlAsync(caId);
        var bcSubCa = DotNetUtilities.FromX509Certificate(subCaCert);

        // Signed by the selected certificate's key (not by anything else)
        Should.NotThrow(() => crl.Verify(bcSubCa.GetPublicKey()));

        // Issuer DN is byte-for-byte the certificate's subject
        crl.IssuerDN.Equivalent(bcSubCa.SubjectDN, inOrder: true).ShouldBeTrue();

        // AKI equals the certificate's SKI as issued by the external CA
        GetCrlAuthorityKeyIdentifier(crl).ShouldBe(ExternalSki);

        // CRL number extension present and equal to 1
        GetCrlNumber(crl).ShouldBe(BigInteger.One);

        crl.NextUpdate.ShouldNotBeNull();
        crl.NextUpdate!.Value.ShouldBeGreaterThan(crl.ThisUpdate);
    }

    [Fact]
    public async Task GenerateCrlAsync_EcdsaImportedSubCa_SignsWithEcdsa()
    {
        var (caId, subCaCert) = await SeedImportedSubCaAsync("ECDSA");

        var result = await _service.GenerateCrlAsync(caId);

        result.IsSuccess.ShouldBeTrue(result.Error);

        var crl = await LoadLatestCrlAsync(caId);
        var bcSubCa = DotNetUtilities.FromX509Certificate(subCaCert);
        Should.NotThrow(() => crl.Verify(bcSubCa.GetPublicKey()));
        crl.SigAlgName.ShouldContain("ECDSA", Case.Insensitive);
        GetCrlAuthorityKeyIdentifier(crl).ShouldBe(ExternalSki);
    }

    [Fact]
    public async Task GenerateCrlAsync_IncludesRevokedIssuedCertsAndIncrementsCrlNumber()
    {
        var (caId, _) = await SeedImportedSubCaAsync("RSA");
        var revokedSerial = await SeedRevokedIssuedCertificateAsync(caId, reason: 1 /* keyCompromise */);

        var first = await _service.GenerateCrlAsync(caId);
        first.IsSuccess.ShouldBeTrue(first.Error);
        first.CrlNumber.ShouldBe(1);
        first.RevokedCount.ShouldBe(1);

        var second = await _service.GenerateCrlAsync(caId);
        second.IsSuccess.ShouldBeTrue(second.Error);
        second.CrlNumber.ShouldBe(2);

        await using var db = _dbFactory.CreateDbContext();
        var crls = await db.Crls.Where(c => c.CaCertificateId == caId).OrderBy(c => c.CrlNumber).ToListAsync();
        crls.Count.ShouldBe(2);
        crls[0].IsArchived.ShouldBeTrue();
        crls[1].IsArchived.ShouldBeFalse();

        var crl = new X509CrlParser().ReadCrl(crls[1].RawBytes);
        var entry = crl.GetRevokedCertificate(new BigInteger(revokedSerial, 16));
        entry.ShouldNotBeNull();
        GetCrlNumber(crl).ShouldBe(BigInteger.Two);
    }

    [Fact]
    public async Task GenerateCrlAsync_CaWithoutPrivateKey_Fails()
    {
        var (caId, _) = await SeedImportedSubCaAsync("RSA", includePrivateKey: false);

        var result = await _service.GenerateCrlAsync(caId);

        result.IsSuccess.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("no PFX key");
    }

    // --- Seeding helpers ---

    /// <summary>
    /// Creates an external root (never stored) and a sub-CA signed by it, then stores only the
    /// sub-CA — with ParentId null, exactly as the importer does when the issuer is unknown.
    /// </summary>
    private async Task<(int CaId, X509Certificate2 SubCaCert)> SeedImportedSubCaAsync(
        string algorithm, bool includePrivateKey = true)
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=External Root CA, O=Somebody Else",
            rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(10));

        AsymmetricAlgorithm subKey;
        CertificateRequest subReq;
        if (algorithm == "RSA")
        {
            var rsa = RSA.Create(2048);
            subKey = rsa;
            subReq = new CertificateRequest("CN=Imported Sub CA, OU=PKI, O=My Org",
                rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            subKey = ecdsa;
            subReq = new CertificateRequest("CN=Imported Sub CA, OU=PKI, O=My Org", ecdsa, HashAlgorithmName.SHA256);
        }

        subReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        subReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        subReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(ExternalSki, false));
        subReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            rootCert, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var subPublicOnly = subReq.Create(rootCert.SubjectName, X509SignatureGenerator.CreateForRSA(rootRsa, RSASignaturePadding.Pkcs1), DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5), serial);

        X509Certificate2 subCaCert = subKey switch
        {
            RSA r => subPublicOnly.CopyWithPrivateKey(r),
            ECDsa e => subPublicOnly.CopyWithPrivateKey(e),
            _ => throw new InvalidOperationException()
        };
        subKey.Dispose();

        await using var db = _dbFactory.CreateDbContext();

        var trustDomain = await db.TrustDomains.FirstOrDefaultAsync();
        if (trustDomain == null)
        {
            trustDomain = new TrustDomain { Name = "Test TrustDomain", Enabled = true, CrlValidityDays = 7 };
            db.TrustDomains.Add(trustDomain);
            await db.SaveChangesAsync();
        }

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            ParentId = null, // external issuer is not in the database
            Name = "imported-sub-ca",
            Subject = subCaCert.Subject,
            X509CertificatePem = subCaCert.ExportCertificatePem(),
            EncryptedPfxBytes = includePrivateKey ? subCaCert.Export(X509ContentType.Pkcs12, "import-pw") : null,
            PfxPassword = includePrivateKey ? "import-pw" : null,
            Thumbprint = subCaCert.Thumbprint,
            SerialNumber = subCaCert.SerialNumber,
            KeyAlgorithm = algorithm,
            KeySize = algorithm == "RSA" ? 2048 : 256,
            NotBefore = subCaCert.NotBefore.ToUniversalTime(),
            NotAfter = subCaCert.NotAfter.ToUniversalTime(),
            CertSecurityLevel = CertSecurityLevel.Software,
            Enabled = true
        };

        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        // Return a public-only copy so the test's verification can't accidentally use the key
        var publicCopy = X509CertificateLoader.LoadCertificate(subCaCert.RawData);
        subCaCert.Dispose();
        return (ca.Id, publicCopy);
    }

    private async Task<string> SeedRevokedIssuedCertificateAsync(int caId, int reason)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Revoked Leaf", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = caId,
            Name = "revoked-leaf",
            Subject = cert.Subject,
            X509CertificatePem = cert.ExportCertificatePem(),
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            IsRevoked = true,
            RevokedAt = DateTime.UtcNow.AddMinutes(-5),
            RevocationReason = reason,
            Enabled = true
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();
        return cert.SerialNumber;
    }

    // --- CRL inspection helpers ---

    private async Task<X509Crl> LoadLatestCrlAsync(int caId)
    {
        await using var db = _dbFactory.CreateDbContext();
        var crlEntity = await db.Crls
            .Where(c => c.CaCertificateId == caId && !c.IsArchived)
            .OrderByDescending(c => c.CrlNumber)
            .FirstAsync();
        return new X509CrlParser().ReadCrl(crlEntity.RawBytes);
    }

    private static byte[] GetCrlAuthorityKeyIdentifier(X509Crl crl)
    {
        var octets = crl.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        octets.ShouldNotBeNull("CRL is missing the Authority Key Identifier extension");
        var aki = AuthorityKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(octets));
        return aki.KeyIdentifier.GetOctets();
    }

    private static BigInteger GetCrlNumber(X509Crl crl)
    {
        var octets = crl.GetExtensionValue(X509Extensions.CrlNumber);
        octets.ShouldNotBeNull("CRL is missing the CRL Number extension");
        return CrlNumber.GetInstance(X509ExtensionUtilities.FromExtensionValue(octets)).PositiveValue;
    }
}
