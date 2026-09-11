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
using Sigyll.Common.Services;
using Sigyll.Common.ViewModels;

namespace Sigyll.Signing.Tests;

/// <summary>
/// End of the stand-alone CSR flow: the operator has the .key Sigyll produced and the certificate
/// the external CA signed for that CSR, and needs a .p12. Exercises the real hand-off by running
/// the CSR service first and "signing" its output with a test CA.
/// </summary>
public class Pkcs12BundleServiceTests
{
    private readonly Pkcs12BundleService _service = new(NullLogger<Pkcs12BundleService>.Instance);
    private readonly CsrGenerationService _csrService = new(new TestDbContextFactory(), NullLogger<CsrGenerationService>.Instance);

    private const string KeyPass = "key-passphrase";
    private const string P12Pass = "p12-password";

    [Fact]
    public void Assemble_FromCsrKeyAndCaSignedCert_ProducesLoadablePkcs12()
    {
        var (keyPem, signedCert, caCert) = RunCsrRoundTrip("RSA");

        var result = _service.Assemble(signedCert.RawData, "signed.cer", keyPem, KeyPass, [], P12Pass, "renewed client");

        result.Success.ShouldBeTrue(result.Error);
        result.SuggestedFileName.ShouldBe("renewed-client.p12");
        result.KeyAlgorithm.ShouldBe("RSA");
        result.Thumbprint.ShouldBe(signedCert.Thumbprint);
        result.ChainDer.ShouldBeEmpty();

        using var loaded = X509CertificateLoader.LoadPkcs12(result.Pkcs12Bytes!, P12Pass,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        loaded.HasPrivateKey.ShouldBeTrue();
        loaded.Thumbprint.ShouldBe(signedCert.Thumbprint);

        // The key inside really signs for the certificate's public key
        using var priv = loaded.GetRSAPrivateKey()!;
        byte[] data = [1, 2, 3];
        var sig = priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signedCert.GetRSAPublicKey()!.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();

        caCert.Dispose();
        signedCert.Dispose();
    }

    [Fact]
    public void Assemble_Ecdsa_Works()
    {
        var (keyPem, signedCert, caCert) = RunCsrRoundTrip("ECDSA");

        var result = _service.Assemble(signedCert.RawData, "signed.cer", keyPem, KeyPass, [], P12Pass);

        result.Success.ShouldBeTrue(result.Error);
        result.KeyAlgorithm.ShouldBe("ECDSA");
        result.KeySize.ShouldBe(384);

        using var loaded = X509CertificateLoader.LoadPkcs12(result.Pkcs12Bytes!, P12Pass,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        loaded.GetECDsaPrivateKey().ShouldNotBeNull();

        caCert.Dispose();
        signedCert.Dispose();
    }

    [Fact]
    public void Assemble_WithChainFileAndPemBundle_IncludesChainIssuerFirst()
    {
        var (keyPem, signedCert, caCert) = RunCsrRoundTrip("RSA");

        // CA returned a PEM bundle: leaf followed by issuer; operator also dropped the root separately
        var pemBundle = signedCert.ExportCertificatePem() + "\n" + caCert.ExportCertificatePem();
        var result = _service.Assemble(
            System.Text.Encoding.ASCII.GetBytes(pemBundle), "bundle.pem",
            keyPem, KeyPass,
            [caCert.RawData /* duplicate — must be de-duplicated */],
            P12Pass);

        result.Success.ShouldBeTrue(result.Error);
        result.Thumbprint.ShouldBe(signedCert.Thumbprint);
        result.ChainDer.Count.ShouldBe(1);
        X509CertificateLoader.LoadCertificate(result.ChainDer[0]).Thumbprint.ShouldBe(caCert.Thumbprint);

        var collection = X509CertificateLoader.LoadPkcs12Collection(result.Pkcs12Bytes!, P12Pass,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        collection.Count.ShouldBe(2);
        collection.Cast<X509Certificate2>().Count(c => c.HasPrivateKey).ShouldBe(1);
        collection.Cast<X509Certificate2>().Single(c => c.HasPrivateKey).Thumbprint.ShouldBe(signedCert.Thumbprint);

        caCert.Dispose();
        signedCert.Dispose();
    }

    [Fact]
    public void Assemble_WrongPassphrase_FailsClearly()
    {
        var (keyPem, signedCert, caCert) = RunCsrRoundTrip("RSA");

        var result = _service.Assemble(signedCert.RawData, "signed.cer", keyPem, "nope", [], P12Pass);

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("passphrase", Case.Insensitive);

        caCert.Dispose();
        signedCert.Dispose();
    }

    [Fact]
    public void Assemble_KeyDoesNotMatchCertificate_Fails()
    {
        var (_, signedCert, caCert) = RunCsrRoundTrip("RSA");
        using var otherKey = RSA.Create(2048);
        var otherPem = otherKey.ExportEncryptedPkcs8PrivateKeyPem(KeyPass,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));

        var result = _service.Assemble(signedCert.RawData, "signed.cer", otherPem, KeyPass, [], P12Pass);

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("does not match");

        caCert.Dispose();
        signedCert.Dispose();
    }

    [Fact]
    public void Assemble_PlainUnencryptedKey_Works()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Plain Key", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        using var publicOnly = X509CertificateLoader.LoadCertificate(cert.RawData);

        var result = _service.Assemble(publicOnly.RawData, "plain.cer", rsa.ExportPkcs8PrivateKeyPem(), null, [], P12Pass);

        result.Success.ShouldBeTrue(result.Error);
        result.SuggestedFileName.ShouldBe("Plain-Key.p12");
    }

    [Fact]
    public void Assemble_MissingP12Password_Fails()
    {
        var (keyPem, signedCert, caCert) = RunCsrRoundTrip("RSA");

        var result = _service.Assemble(signedCert.RawData, "signed.cer", keyPem, KeyPass, [], "");

        result.Success.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
        result.Error.ShouldContain("password");

        caCert.Dispose();
        signedCert.Dispose();
    }

    /// <summary>
    /// Plays the whole external-CA scenario: model certificate → new-key CSR via the CSR service →
    /// a test CA signs the CSR → returns (encrypted key PEM, signed certificate, CA certificate).
    /// </summary>
    private (string KeyPem, X509Certificate2 SignedCert, X509Certificate2 CaCert) RunCsrRoundTrip(string algorithm)
    {
        // The certificate the operator already has (public part is enough for a new-key CSR)
        using var oldRsa = RSA.Create(2048);
        var oldReq = new CertificateRequest("CN=UDAP Client, O=My Org", oldRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri("https://fhir.example.org/r4"));
        oldReq.CertificateExtensions.Add(san.Build());
        using var oldCert = oldReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddDays(5));

        var csr = _csrService.GenerateCsrFromCertificate(oldCert, "udap-client", new CsrGenerationRequest
        {
            KeyMode = CsrKeyMode.GenerateNewKey,
            NewKeyAlgorithm = algorithm,
            NewKeySize = algorithm == "RSA" ? 2048 : 384,
            NewKeyPassphrase = KeyPass
        });
        csr.Success.ShouldBeTrue(csr.Error);

        // External CA signs the CSR
        using var caRsa = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=External CA", caRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));
        var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        var loadedCsr = CertificateRequest.LoadSigningRequestPem(csr.CsrPem!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var serial = RandomNumberGenerator.GetBytes(12);
        serial[0] &= 0x7F;
        var signed = loadedCsr.Create(caCert.SubjectName,
            X509SignatureGenerator.CreateForRSA(caRsa, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1), serial);

        return (csr.EncryptedPrivateKeyPem!, signed, caCert);
    }
}
