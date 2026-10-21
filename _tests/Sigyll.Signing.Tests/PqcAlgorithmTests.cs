#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using Sigyll.Common.Services.Pqc;
using Sigyll.Common.Services.Signing;

namespace Sigyll.Signing.Tests;

public class PqcAlgorithmTests
{
    [Fact]
    public void Catalog_CoversEveryRuntimeParameterSet()
    {
        var names = RuntimeNames(typeof(MLDsaAlgorithm))
            .Concat(RuntimeNames(typeof(SlhDsaAlgorithm)))
            .Concat(RuntimeNames(typeof(MLKemAlgorithm)))
            .Concat(RuntimeNames(typeof(CompositeMLDsaAlgorithm)))
            .ToArray();

        names.Length.ShouldBeGreaterThan(30);
        foreach (var name in names)
        {
            PqcAlgorithms.TryGet(name, out var info).ShouldBeTrue($"missing {name}");
            info.Id.ShouldBe(name);
            info.Id.Length.ShouldBeLessThanOrEqualTo(64);
        }

        PqcAlgorithms.ParameterSets.Count.ShouldBe(names.Length);
    }

    [Fact]
    public void Canonicalize_AcceptsFamilyPlusSize()
    {
        PqcAlgorithms.Canonicalize("ML-DSA", 87).ShouldBe("ML-DSA-87");
        PqcAlgorithms.Canonicalize("ML-KEM", 1024).ShouldBe("ML-KEM-1024");
        PqcAlgorithms.Canonicalize("ML-DSA-65", 0).ShouldBe("ML-DSA-65");
        PqcAlgorithms.Canonicalize("RSA", 2048).ShouldBeNull();
    }

    [Fact]
    public void Kem_CannotSignACsr()
    {
        PqcAlgorithms.IsKem("ML-KEM-768").ShouldBeTrue();
        PqcAlgorithms.IsKem("ML-DSA-87").ShouldBeFalse();
        PqcAlgorithms.CsrAlgorithms.ShouldContain("ML-DSA-87");
        PqcAlgorithms.CsrAlgorithms.ShouldContain("SLH-DSA-SHA2-128s");
        PqcAlgorithms.CsrAlgorithms.ShouldNotContain("ML-KEM-1024");

        var ex = Should.Throw<InvalidOperationException>(() => CsrSigningKey.Generate("ML-KEM-1024", 1024));
        ex.Message.ShouldContain("cannot sign");
    }

    [Fact]
    public void UnsupportedPlatform_ExplainsWhy()
    {
        if (MLDsa.IsSupported)
            return;

        var reason = PqcAlgorithms.UnsupportedReason("ML-DSA-87");
        reason.ShouldNotBeNull();
        reason.ShouldContain("OpenSSL 3.5");
    }

    [Fact]
    public void TrySliceSigned_RecoversTheTbsAndPkcs1Signature()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=slicer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        PqcCertificateVerifier.TrySliceSigned(cert.RawData, out var tbs, out var signature).ShouldBeTrue();
        rsa.VerifyData(tbs, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();
        PqcCertificateVerifier.TryVerify(cert.RawData, cert.RawData).ShouldBeNull();
    }

    [Fact]
    public async Task LocalProvider_GeneratesMlDsaWhenThePlatformAllowsIt()
    {
        if (!MLDsa.IsSupported)
            return;

        using var provider = new LocalSigningProvider();
        var key = await provider.GenerateKeyAsync("ML-DSA", 87, null);
        key.KeyAlgorithm.ShouldBe("ML-DSA-87");
        key.KeySize.ShouldBe(87);

        var publicKey = await provider.GetRawPublicKeyAsync(key);
        publicKey.Algorithm.ShouldBe("ML-DSA-87");
        publicKey.Bytes.Length.ShouldBeGreaterThan(32);

        var data = new byte[] { 1, 2, 3, 4 };
        var signature = await provider.SignDataAsync(data, HashAlgorithmName.SHA256, key);
        signature.Length.ShouldBeGreaterThan(1000);
    }

    [Fact]
    public void SelfSignedMlDsa_VerifiesAndRoundTripsPfx()
    {
        if (!MLDsa.IsSupported)
            return;

        using var key = PqcKeyPair.Generate("ML-DSA-65");
        var request = key.CreateCertificateRequest("CN=PQC Root");
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        PqcCertificateVerifier.TryVerify(cert.RawData, cert.RawData).ShouldBe(true);
        PqcAlgorithms.DescribeCertificate(cert).Algorithm.ShouldBe("ML-DSA-65");

        var pfx = cert.Export(X509ContentType.Pkcs12, "pqc");
        using var loaded = X509CertificateLoader.LoadPkcs12(pfx, "pqc", X509KeyStorageFlags.Exportable);
        loaded.GetMLDsaPrivateKey().ShouldNotBeNull();
    }

    private static IEnumerable<string> RuntimeNames(Type algorithmType)
    {
        foreach (var property in algorithmType.GetProperties(BindingFlags.Public | BindingFlags.Static))
        {
            if (property.PropertyType != algorithmType || property.GetIndexParameters().Length > 0)
                continue;
            yield return property.GetValue(null)!.ToString()!;
        }
    }
}
