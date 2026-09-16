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
using Sigyll.Common.ViewModels;

namespace Sigyll.Signing.Tests;

/// <summary>
/// Outbound CSRs where Sigyll keeps the key: create → (external CA signs) → fulfil → the
/// certificate is stored with its key and the request is closed. Also covers the shortcut where
/// the returned .cer is simply imported and recognised.
/// </summary>
public class ExternalCertificateRequestServiceTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();
    private readonly ExternalCertificateRequestService _service;
    private readonly CertificateImportService _importService;

    private const string SanUri = "https://shin-sand-idp.dev.surescripts.tech";

    public ExternalCertificateRequestServiceTests()
    {
        _importService = new CertificateImportService(_dbFactory, NullLogger<CertificateImportService>.Instance);
        _service = new ExternalCertificateRequestService(
            _dbFactory,
            NullLogger<ExternalCertificateRequestService>.Instance,
            new Pkcs12BundleService(NullLogger<Pkcs12BundleService>.Instance),
            new CertificateParsingService(),
            _importService);
    }

    // ------------------------------------------------------------------ create

    [Fact]
    public async Task Create_UdapClientProfile_StoresKeyAndProducesValidCsr()
    {
        var tdId = await SeedTrustDomainAsync();

        var result = await _service.CreateAsync(new CreateExternalCertificateRequest
        {
            TrustDomainId = tdId,
            Name = "fhirlabs client",
            SubjectDn = "CN=https://fhirlabs.net/fhir/r4, O=Surescripts LLC, C=US",
            SubjectAltNames = [new SanEntry(SanType.Uri, SanUri), new SanEntry(SanType.Uri, "https://fhirlabs.net/fhir/r4")],
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            Profile = CsrExtensionProfile.UdapClient,
            ExternalCaName = "EMR Direct"
        });

        result.Success.ShouldBeTrue(result.Error);
        result.RequestId.ShouldNotBeNull();

        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        csr.SubjectName.Name.ShouldBe("CN=https://fhirlabs.net/fhir/r4, O=Surescripts LLC, C=US");
        csr.CertificateExtensions.OfType<X509KeyUsageExtension>().Single().KeyUsages.ShouldBe(X509KeyUsageFlags.DigitalSignature);
        csr.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().Single()
            .EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ShouldBe(["1.3.6.1.5.5.7.3.2"]);

        // SAN text verbatim — no trailing slash on the bare host
        var sanExt = csr.CertificateExtensions.Single(e => e.Oid?.Value == "2.5.29.17");
        using var probe = WrapExtension(sanExt);
        CsrGenerationService.ExtractSubjectAltNames(probe)
            .ShouldBe([new SanEntry(SanType.Uri, SanUri), new SanEntry(SanType.Uri, "https://fhirlabs.net/fhir/r4")]);

        // Stored row: key decrypts with the stored password and matches the CSR's public key
        await using var db = _dbFactory.CreateDbContext();
        var row = await db.ExternalCertificateRequests.SingleAsync();
        row.Status.ShouldBe(ExternalRequestStatus.Pending);
        row.ExternalCaName.ShouldBe("EMR Direct");
        row.PublicKeyThumbprint.ShouldBe(Convert.ToHexString(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo())));
        row.EncryptedPrivateKeyPem.ShouldContain("ENCRYPTED PRIVATE KEY");
        using var key = RSA.Create();
        key.ImportFromEncryptedPem(row.EncryptedPrivateKeyPem, row.KeyPassword);
        key.ExportSubjectPublicKeyInfo().ShouldBe(csr.PublicKey.ExportSubjectPublicKeyInfo());

        var summary = (await _service.ListAsync(tdId, includeCompleted: false)).Single();
        summary.SubjectAltNames.Count.ShouldBe(2);
        summary.KeyAlgorithm.ShouldBe("RSA");
    }

    [Fact]
    public async Task Create_FromModeledCertificate_CopiesExtensionsAndRecordsModel()
    {
        var tdId = await SeedTrustDomainAsync();
        var (caId, issuedId, _) = await SeedCaAndIssuedAsync(tdId);

        var result = await _service.CreateAsync(new CreateExternalCertificateRequest
        {
            TrustDomainId = tdId,
            Name = "renewal",
            SubjectDn = "CN=Old Client, O=My Org",
            KeyAlgorithm = "ECDSA",
            KeySize = 384,
            Profile = CsrExtensionProfile.FromModeledCertificate,
            ModeledOnCertificateId = issuedId,
            ModeledOnEntityType = "IssuedCertificate"
        });

        result.Success.ShouldBeTrue(result.Error);
        var csr = CertificateRequest.LoadSigningRequestPem(result.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        csr.CertificateExtensions.OfType<X509KeyUsageExtension>().Single().KeyUsages
            .ShouldBe(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation);

        var summary = await _service.GetAsync(result.RequestId!.Value);
        summary!.ModeledOnCertificateId.ShouldBe(issuedId);
        summary.KeyAlgorithm.ShouldBe("ECDSA");
        summary.KeySize.ShouldBe(384);
        _ = caId;
    }

    [Fact]
    public async Task Create_FromModeledCertificate_WithoutModel_Fails()
    {
        var tdId = await SeedTrustDomainAsync();
        var result = await _service.CreateAsync(new CreateExternalCertificateRequest
        {
            TrustDomainId = tdId, Name = "x", SubjectDn = "CN=x", Profile = CsrExtensionProfile.FromModeledCertificate
        });
        result.Success.ShouldBeFalse();
    }

    // ------------------------------------------------------------------ update

    [Fact]
    public async Task Update_RegeneratesCsrWithSameKey_ByDefault()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));
        var id = created.RequestId!.Value;

        // CA rejected it: fix the subject, add a SAN, switch profile, and note the CA name
        var updated = await _service.UpdateAsync(new UpdateExternalCertificateRequest
        {
            Id = id,
            Name = "basic (fixed)",
            SubjectDn = "CN=basic, OU=Integration, O=My Org, C=US",
            SubjectAltNames = [new SanEntry(SanType.Uri, SanUri), new SanEntry(SanType.Uri, "https://fhirlabs.net/fhir/r4")],
            Profile = CsrExtensionProfile.TlsServerAndClient,
            ExternalCaName = "EMR Direct"
        });

        updated.Success.ShouldBeTrue(updated.Error);
        updated.CsrPem.ShouldNotBe(created.CsrPem);
        updated.PublicKeyThumbprint.ShouldBe(created.PublicKeyThumbprint); // same key pair

        var csr = CertificateRequest.LoadSigningRequestPem(updated.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        csr.SubjectName.Name.ShouldBe("CN=basic, OU=Integration, O=My Org, C=US");
        csr.CertificateExtensions.OfType<X509KeyUsageExtension>().Single().KeyUsages
            .ShouldBe(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        csr.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().Single()
            .EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ShouldBe(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]);

        var summary = await _service.GetAsync(id);
        summary!.Name.ShouldBe("basic (fixed)");
        summary.SubjectAltNames.Count.ShouldBe(2);
        summary.Profile.ShouldBe(CsrExtensionProfile.TlsServerAndClient);
        summary.ExternalCaName.ShouldBe("EMR Direct");
        summary.UpdatedAt.ShouldNotBeNull();
        summary.Status.ShouldBe(ExternalRequestStatus.Pending);

        // The stored CSR is the regenerated one and the stored key still signs for it
        var export = await _service.ExportCsrAsync(id);
        export.Content.ShouldBe(updated.CsrPem);
        using var keyExport = RSA.Create();
        keyExport.ImportFromEncryptedPem((await _service.ExportPrivateKeyAsync(id, "pw")).Content!, "pw");
        keyExport.ExportSubjectPublicKeyInfo().ShouldBe(csr.PublicKey.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public async Task Update_WithRegenerateKey_RotatesKeyPair()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));
        var id = created.RequestId!.Value;

        var updated = await _service.UpdateAsync(new UpdateExternalCertificateRequest
        {
            Id = id,
            Name = "basic",
            SubjectDn = "CN=basic, O=My Org",
            SubjectAltNames = [new SanEntry(SanType.Uri, SanUri)],
            Profile = CsrExtensionProfile.UdapClient,
            RegenerateKey = true,
            KeyAlgorithm = "ECDSA",
            KeySize = 256
        });

        updated.Success.ShouldBeTrue(updated.Error);
        updated.PublicKeyThumbprint.ShouldNotBe(created.PublicKeyThumbprint);

        var summary = await _service.GetAsync(id);
        summary!.KeyAlgorithm.ShouldBe("ECDSA");
        summary.KeySize.ShouldBe(256);

        // New key decrypts and matches the new CSR
        var csr = CertificateRequest.LoadSigningRequestPem(updated.CsrPem!, HashAlgorithmName.SHA256);
        using var key = ECDsa.Create();
        key.ImportFromEncryptedPem((await _service.ExportPrivateKeyAsync(id, "pw")).Content!, "pw");
        key.ExportSubjectPublicKeyInfo().ShouldBe(csr.PublicKey.ExportSubjectPublicKeyInfo());

        // The regenerated request can still be fulfilled end-to-end
        var (caId, _, caCert) = await SeedCaAndIssuedAsync(tdId);
        using var signed = SignCsr(updated.CsrPem!, caCert);
        var fulfilled = await _service.FulfillAsync(id, signed.RawData, "signed.cer", []);
        fulfilled.Success.ShouldBeTrue(fulfilled.Error);
        _ = caId;
    }

    [Fact]
    public async Task Update_NonPendingOrInvalid_Fails()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));
        var id = created.RequestId!.Value;

        (await _service.UpdateAsync(new UpdateExternalCertificateRequest { Id = id, Name = "x", SubjectDn = "this is not a DN" }))
            .Success.ShouldBeFalse();
        (await _service.UpdateAsync(new UpdateExternalCertificateRequest
            { Id = id, Name = "x", SubjectDn = "CN=x", Profile = CsrExtensionProfile.FromModeledCertificate }))
            .Success.ShouldBeFalse(); // no modeled certificate on this request

        await _service.CancelAsync(id);
        var afterCancel = await _service.UpdateAsync(new UpdateExternalCertificateRequest { Id = id, Name = "x", SubjectDn = "CN=x" });
        afterCancel.Success.ShouldBeFalse();
        afterCancel.Error.ShouldNotBeNull();
        afterCancel.Error.ShouldContain("pending");

        (await _service.UpdateAsync(new UpdateExternalCertificateRequest { Id = 99999, Name = "x", SubjectDn = "CN=x" }))
            .Success.ShouldBeFalse();
    }

    // ------------------------------------------------------------------ export

    [Fact]
    public async Task ExportPrivateKey_ReencryptsUnderOperatorPassphrase()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));

        var export = await _service.ExportPrivateKeyAsync(created.RequestId!.Value, "operator-pass");

        export.Success.ShouldBeTrue(export.Error);
        export.FileName.ShouldBe("basic.key");
        using var key = RSA.Create();
        key.ImportFromEncryptedPem(export.Content!, "operator-pass");
        var csr = CertificateRequest.LoadSigningRequestPem(created.CsrPem!, HashAlgorithmName.SHA256);
        key.ExportSubjectPublicKeyInfo().ShouldBe(csr.PublicKey.ExportSubjectPublicKeyInfo());

        (await _service.ExportPrivateKeyAsync(created.RequestId.Value, "")).Success.ShouldBeFalse();

        var csrExport = await _service.ExportCsrAsync(created.RequestId.Value);
        csrExport.Success.ShouldBeTrue();
        csrExport.FileName.ShouldBe("basic.csr");
        csrExport.Content.ShouldBe(created.CsrPem);
    }

    // ------------------------------------------------------------------ fulfil

    [Fact]
    public async Task Fulfill_WithIssuerInTrustDomain_ImportsCertificateWithKeyAndClosesRequest()
    {
        var tdId = await SeedTrustDomainAsync();
        var (caId, issuedId, caCert) = await SeedCaAndIssuedAsync(tdId);   // this CA plays the "external" issuer, already trusted
        var created = await _service.CreateAsync(new CreateExternalCertificateRequest
        {
            TrustDomainId = tdId, Name = "renewed client", SubjectDn = "CN=Old Client, O=My Org",
            Profile = CsrExtensionProfile.UdapClient,
            ModeledOnCertificateId = issuedId, ModeledOnEntityType = "IssuedCertificate"
        });

        using var signed = SignCsr(created.CsrPem!, caCert);

        var result = await _service.FulfillAsync(created.RequestId!.Value, signed.RawData, "renewed.cer", []);

        result.Success.ShouldBeTrue(result.Error);
        result.EntityType.ShouldBe("IssuedCertificate");
        result.Thumbprint.ShouldBe(signed.Thumbprint);
        result.ImportedName.ShouldBe("renewed client");

        await using var db = _dbFactory.CreateDbContext();
        var stored = await db.IssuedCertificates.SingleAsync(i => i.Thumbprint == signed.Thumbprint);
        stored.IssuingCaCertificateId.ShouldBe(caId);
        stored.EncryptedPfxBytes.ShouldNotBeNull();
        stored.RenewalOfId.ShouldBe(issuedId);
        stored.Version.ShouldBe(2);
        using var pfx = X509CertificateLoader.LoadPkcs12(stored.EncryptedPfxBytes!, stored.PfxPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        pfx.HasPrivateKey.ShouldBeTrue();

        var row = await db.ExternalCertificateRequests.SingleAsync();
        row.Status.ShouldBe(ExternalRequestStatus.Fulfilled);
        row.FulfilledCertificateId.ShouldBe(stored.Id);
        row.FulfilledEntityType.ShouldBe("IssuedCertificate");
        row.FulfilledThumbprint.ShouldBe(signed.Thumbprint);

        // Second attempt is refused
        (await _service.FulfillAsync(created.RequestId.Value, signed.RawData, "renewed.cer", [])).Success.ShouldBeFalse();
    }

    [Fact]
    public async Task ExportPkcs12_AfterFulfilment_UsesOperatorPasswordAndOptionalChain()
    {
        var tdId = await SeedTrustDomainAsync();
        var (_, _, caCert) = await SeedCaAndIssuedAsync(tdId);
        var created = await _service.CreateAsync(Basic(tdId));
        var id = created.RequestId!.Value;

        // Not fulfilled yet → nothing to bundle
        (await _service.ExportPkcs12Async(id, "pw", includeChain: true)).Success.ShouldBeFalse();

        using var signed = SignCsr(created.CsrPem!, caCert);
        (await _service.FulfillAsync(id, signed.RawData, "signed.cer", [])).Success.ShouldBeTrue();

        var leafOnly = await _service.ExportPkcs12Async(id, "operator-p12-pw", includeChain: false);
        leafOnly.Success.ShouldBeTrue(leafOnly.Error);
        leafOnly.FileName.ShouldBe("basic.p12");
        var single = X509CertificateLoader.LoadPkcs12Collection(leafOnly.Bytes!, "operator-p12-pw",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        single.Count.ShouldBe(1);
        single[0].HasPrivateKey.ShouldBeTrue();
        single[0].Thumbprint.ShouldBe(signed.Thumbprint);

        var withChain = await _service.ExportPkcs12Async(id, "operator-p12-pw", includeChain: true);
        withChain.Success.ShouldBeTrue(withChain.Error);
        withChain.FileName.ShouldBe("basic-chain.p12");
        var bundle = X509CertificateLoader.LoadPkcs12Collection(withChain.Bytes!, "operator-p12-pw",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        bundle.Count.ShouldBe(2);
        bundle.Cast<X509Certificate2>().Single(c => c.HasPrivateKey).Thumbprint.ShouldBe(signed.Thumbprint);
        bundle.Cast<X509Certificate2>().Single(c => !c.HasPrivateKey).Thumbprint.ShouldBe(caCert.Thumbprint);

        (await _service.ExportPkcs12Async(id, "", includeChain: false)).Success.ShouldBeFalse();
    }

    [Fact]
    public async Task Fulfill_UnknownIssuer_ReportsNeedsCaSelection_ThenSucceedsWithChain()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));
        using var externalCa = MakeCa("CN=Truly External CA");
        using var signed = SignCsr(created.CsrPem!, externalCa);

        var first = await _service.FulfillAsync(created.RequestId!.Value, signed.RawData, "signed.cer", []);
        first.Success.ShouldBeFalse();
        first.NeedsCaSelection.ShouldBeTrue();
        first.IssuerName.ShouldContain("Truly External CA");

        // Still pending
        (await _service.GetAsync(created.RequestId.Value))!.Status.ShouldBe(ExternalRequestStatus.Pending);

        // Provide the chain: the CA is imported as a trust anchor, then the leaf resolves
        var second = await _service.FulfillAsync(created.RequestId.Value, signed.RawData, "signed.cer", [externalCa.RawData]);
        second.Success.ShouldBeTrue(second.Error);
        second.ChainCertificatesImported.ShouldBe(1);

        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.CountAsync(c => c.Thumbprint == externalCa.Thumbprint)).ShouldBe(1);
        (await db.IssuedCertificates.CountAsync(i => i.Thumbprint == signed.Thumbprint)).ShouldBe(1);
    }

    [Fact]
    public async Task Fulfill_CertificateForDifferentKey_Fails()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));
        var other = await _service.CreateAsync(Basic(tdId, "other"));
        using var ca = MakeCa("CN=Some CA");
        using var signedForOther = SignCsr(other.CsrPem!, ca);

        var result = await _service.FulfillAsync(created.RequestId!.Value, signedForOther.RawData, "wrong.cer", [ca.RawData]);

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("does not match");
    }

    [Fact]
    public async Task ImportingReturnedCertificateDirectly_RecognisesPendingRequest()
    {
        // The shortcut: operator drops the CA's .cer into the Explorer instead of using Complete
        var tdId = await SeedTrustDomainAsync();
        var (caId, _, caCert) = await SeedCaAndIssuedAsync(tdId);
        var created = await _service.CreateAsync(Basic(tdId));
        using var signed = SignCsr(created.CsrPem!, caCert);

        var parsed = new CertificateParsingService().Parse(signed.RawData, "returned.cer")!;
        var import = await _importService.ImportParsedCertificateAsync(parsed, tdId, name: "returned", issuingCaId: caId);
        parsed.Certificate.Dispose();

        import.Success.ShouldBeTrue(import.Error);
        import.KeyPairedFrom.ShouldNotBeNull();
        import.KeyPairedFrom.ShouldContain("basic");

        await using var db = _dbFactory.CreateDbContext();
        var stored = await db.IssuedCertificates.SingleAsync(i => i.Thumbprint == signed.Thumbprint);
        stored.EncryptedPfxBytes.ShouldNotBeNull();
        var row = await db.ExternalCertificateRequests.SingleAsync();
        row.Status.ShouldBe(ExternalRequestStatus.Fulfilled);
        row.FulfilledCertificateId.ShouldBe(stored.Id);
    }

    // ------------------------------------------------------------------ lifecycle

    [Fact]
    public async Task CancelAndDelete()
    {
        var tdId = await SeedTrustDomainAsync();
        var created = await _service.CreateAsync(Basic(tdId));
        var id = created.RequestId!.Value;

        (await _service.CancelAsync(id)).ShouldBeTrue();
        (await _service.GetAsync(id))!.Status.ShouldBe(ExternalRequestStatus.Cancelled);
        (await _service.CancelAsync(id)).ShouldBeFalse(); // already cancelled

        (await _service.ListAsync(tdId, includeCompleted: false)).ShouldBeEmpty();
        (await _service.ListAsync(tdId, includeCompleted: true)).Count.ShouldBe(1);

        (await _service.DeleteAsync(id)).ShouldBeTrue();
        (await _service.GetAsync(id)).ShouldBeNull();
    }

    // ------------------------------------------------------------------ helpers

    private static CreateExternalCertificateRequest Basic(int tdId, string name = "basic") => new()
    {
        TrustDomainId = tdId,
        Name = name,
        SubjectDn = $"CN={name}, O=My Org",
        SubjectAltNames = [new SanEntry(SanType.Uri, SanUri)],
        Profile = CsrExtensionProfile.UdapClient
    };

    private async Task<int> SeedTrustDomainAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var td = new TrustDomain { Name = "External Requests Test", Enabled = true };
        db.TrustDomains.Add(td);
        await db.SaveChangesAsync();
        return td.Id;
    }

    private static X509Certificate2 MakeCa(string subject)
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    /// <summary>Seeds a CA (trust anchor with key, kept in memory for signing) and one issued cert with KU digitalSignature+nonRepudiation.</summary>
    private async Task<(int CaId, int IssuedId, X509Certificate2 CaCert)> SeedCaAndIssuedAsync(int tdId)
    {
        var caCert = MakeCa("CN=Trusted Issuer");

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Old Client, O=My Org", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        var serial = RandomNumberGenerator.GetBytes(8); serial[0] &= 0x7F;
        using var leaf = leafReq.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);

        await using var db = _dbFactory.CreateDbContext();
        var ca = new CaCertificate
        {
            TrustDomainId = tdId, Name = "trusted-issuer", Subject = caCert.Subject,
            X509CertificatePem = caCert.ExportCertificatePem(), Thumbprint = caCert.Thumbprint,
            SerialNumber = caCert.SerialNumber, KeyAlgorithm = "RSA", KeySize = 2048,
            NotBefore = caCert.NotBefore.ToUniversalTime(), NotAfter = caCert.NotAfter.ToUniversalTime()
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        var issued = new IssuedCertificate
        {
            IssuingCaCertificateId = ca.Id, Name = "old client", Subject = leaf.Subject,
            X509CertificatePem = leaf.ExportCertificatePem(), Thumbprint = leaf.Thumbprint,
            SerialNumber = leaf.SerialNumber, KeyAlgorithm = "RSA", KeySize = 2048,
            NotBefore = leaf.NotBefore.ToUniversalTime(), NotAfter = leaf.NotAfter.ToUniversalTime()
        };
        db.IssuedCertificates.Add(issued);
        await db.SaveChangesAsync();

        return (ca.Id, issued.Id, caCert);
    }

    /// <summary>Acts as the external CA: signs the PKCS#10 with the given CA certificate (which must carry its key).</summary>
    private static X509Certificate2 SignCsr(string csrPem, X509Certificate2 caWithKey)
    {
        var csr = CertificateRequest.LoadSigningRequestPem(csrPem, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var serial = RandomNumberGenerator.GetBytes(12); serial[0] &= 0x7F;
        using var caRsa = caWithKey.GetRSAPrivateKey()!;
        return csr.Create(caWithKey.SubjectName,
            X509SignatureGenerator.CreateForRSA(caRsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1), serial);
    }

    private static X509Certificate2 WrapExtension(X509Extension extension)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=probe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension(extension.Oid!, extension.RawData, extension.Critical));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
    }
}
