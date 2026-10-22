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

namespace Sigyll.Common.Services.Pqc;

/// <summary>
/// One generated post-quantum key. ML-DSA, SLH-DSA and composite ML-DSA can sign;
/// ML-KEM can only be the subject key of a certificate signed by something else.
/// Pure signatures use an empty context, which is what .NET's X.509 generator uses.
/// </summary>
public sealed class PqcKeyPair : IDisposable
{
    private static readonly byte[] EmptyContext = [];
    private static readonly PbeParameters KeyPbe = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    private readonly MLDsa? _mlDsa;
    private readonly SlhDsa? _slhDsa;
    private readonly MLKem? _mlKem;
    private readonly CompositeMLDsa? _composite;

    private PqcKeyPair(string algorithmId, int keySize, MLDsa? mlDsa = null, SlhDsa? slhDsa = null,
        MLKem? mlKem = null, CompositeMLDsa? composite = null)
    {
        AlgorithmId = algorithmId;
        KeySize = keySize;
        _mlDsa = mlDsa;
        _slhDsa = slhDsa;
        _mlKem = mlKem;
        _composite = composite;
    }

    public string AlgorithmId { get; }
    public int KeySize { get; }
    public bool CanSign => _mlKem == null;

    public static PqcKeyPair Generate(string algorithmId)
    {
        var info = PqcAlgorithms.Require(algorithmId);
        var unsupported = PqcAlgorithms.UnsupportedReason(info.Id);
        if (unsupported != null)
            throw new PlatformNotSupportedException(unsupported);

        return info.Family switch
        {
            "ML-DSA" => new PqcKeyPair(info.Id, info.KeySize, mlDsa: MLDsa.GenerateKey(MlDsaAlgorithm(info.Id))),
            "SLH-DSA" => new PqcKeyPair(info.Id, info.KeySize, slhDsa: SlhDsa.GenerateKey(SlhAlgorithm(info.Id))),
            "ML-KEM" => new PqcKeyPair(info.Id, info.KeySize, mlKem: MLKem.GenerateKey(KemAlgorithm(info.Id))),
            "Composite ML-DSA" => new PqcKeyPair(info.Id, info.KeySize,
                composite: CompositeMLDsa.GenerateKey(CompositeAlgorithm(info.Id))),
            _ => throw new ArgumentException($"Cannot generate '{algorithmId}'.")
        };
    }

    public static PqcKeyPair? FromCertificate(X509Certificate2 certificate)
    {
        if (certificate.GetMLDsaPrivateKey() is { } ml)
            return new PqcKeyPair(ml.Algorithm.Name, PqcAlgorithms.DescribeCertificate(certificate).KeySize, mlDsa: ml);
        if (certificate.GetSlhDsaPrivateKey() is { } slh)
            return new PqcKeyPair(slh.Algorithm.Name, PqcAlgorithms.DescribeCertificate(certificate).KeySize, slhDsa: slh);
        if (certificate.GetCompositeMLDsaPrivateKey() is { } composite)
            return new PqcKeyPair(composite.Algorithm.Name, PqcAlgorithms.DescribeCertificate(certificate).KeySize, composite: composite);
        if (certificate.GetMLKemPrivateKey() is { } kem)
            return new PqcKeyPair(kem.Algorithm.Name, PqcAlgorithms.DescribeCertificate(certificate).KeySize, mlKem: kem);
        return null;
    }

    public static PqcKeyPair ImportEncryptedPkcs8(string algorithmId, string pem, string password)
    {
        var info = PqcAlgorithms.Require(PqcAlgorithms.Canonicalize(algorithmId, 0) ?? algorithmId);
        return info.Family switch
        {
            "ML-DSA" => new PqcKeyPair(info.Id, info.KeySize, mlDsa: MLDsa.ImportFromEncryptedPem(pem, password)),
            "SLH-DSA" => new PqcKeyPair(info.Id, info.KeySize, slhDsa: SlhDsa.ImportFromEncryptedPem(pem, password)),
            "ML-KEM" => new PqcKeyPair(info.Id, info.KeySize, mlKem: MLKem.ImportFromEncryptedPem(pem, password)),
            "Composite ML-DSA" => new PqcKeyPair(info.Id, info.KeySize,
                composite: CompositeMLDsa.ImportFromEncryptedPem(pem, password)),
            _ => throw new ArgumentException($"Cannot import '{algorithmId}'.")
        };
    }

    public CertificateRequest CreateCertificateRequest(X500DistinguishedName subject)
    {
        if (_mlDsa != null) return new CertificateRequest(subject, _mlDsa);
        if (_slhDsa != null) return new CertificateRequest(subject, _slhDsa);
        if (_composite != null) return new CertificateRequest(subject, _composite);
        if (_mlKem != null)
        {
            // ML-KEM has no CertificateRequest constructor: it cannot sign the request.
            // Callers that need a signed PKCS#10 must use a signature algorithm.
            var spki = _mlKem.ExportSubjectPublicKeyInfo();
            var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(spki, out _);
            return new CertificateRequest(subject, publicKey, HashAlgorithmName.SHA256);
        }

        throw new InvalidOperationException("Post-quantum key has no algorithm.");
    }

    public CertificateRequest CreateCertificateRequest(string subjectDn) =>
        CreateCertificateRequest(new X500DistinguishedName(subjectDn));

    public X509Certificate2 CopyWithPrivateKey(X509Certificate2 certificate)
    {
        if (_mlDsa != null) return certificate.CopyWithPrivateKey(_mlDsa);
        if (_slhDsa != null) return certificate.CopyWithPrivateKey(_slhDsa);
        if (_composite != null) return certificate.CopyWithPrivateKey(_composite);
        if (_mlKem != null) return certificate.CopyWithPrivateKey(_mlKem);
        throw new InvalidOperationException("Post-quantum key has no algorithm.");
    }

    public byte[] SignData(byte[] data)
    {
        if (_mlDsa != null) return _mlDsa.SignData(data, EmptyContext);
        if (_slhDsa != null) return _slhDsa.SignData(data, EmptyContext);
        if (_composite != null) return _composite.SignData(data, EmptyContext);
        throw new InvalidOperationException("ML-KEM cannot produce a signature.");
    }

    public byte[] ExportSubjectPublicKeyInfo()
    {
        if (_mlDsa != null) return _mlDsa.ExportSubjectPublicKeyInfo();
        if (_slhDsa != null) return _slhDsa.ExportSubjectPublicKeyInfo();
        if (_mlKem != null) return _mlKem.ExportSubjectPublicKeyInfo();
        if (_composite != null) return _composite.ExportSubjectPublicKeyInfo();
        throw new InvalidOperationException("Post-quantum key has no algorithm.");
    }

    public byte[] ExportEncryptedPkcs8(string password, PbeParameters pbe)
    {
        if (_mlDsa != null) return _mlDsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
        if (_slhDsa != null) return _slhDsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
        if (_mlKem != null) return _mlKem.ExportEncryptedPkcs8PrivateKey(password, pbe);
        if (_composite != null) return _composite.ExportEncryptedPkcs8PrivateKey(password, pbe);
        throw new InvalidOperationException("Post-quantum key has no algorithm.");
    }

    /// <summary>
    /// Reads the ML-KEM key out of a PKCS#12. Windows loads the .pfx but cannot return an
    /// ML-KEM private key from the certificate, so the PKCS#8 is decoded directly.
    /// </summary>
    public static PqcKeyPair ReadKemKey(byte[] pfx, string password)
    {
        var pkcs8 = Pkcs12Writer.ReadPkcs8(pfx, password);
        try
        {
            var kem = MLKem.ImportPkcs8PrivateKey(pkcs8);
            return new PqcKeyPair(kem.Algorithm.Name, PqcAlgorithms.Require(kem.Algorithm.Name).KeySize, mlKem: kem);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    public MLKem Kem => _mlKem ?? throw new InvalidOperationException("This key is not ML-KEM.");

    public string ExportEncryptedPkcs8Pem(string password) => ExportEncryptedPkcs8Pem(password, KeyPbe);

    public string ExportEncryptedPkcs8Pem(string password, PbeParameters pbe)
    {
        if (_mlDsa != null) return _mlDsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbe);
        if (_slhDsa != null) return _slhDsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbe);
        if (_mlKem != null) return _mlKem.ExportEncryptedPkcs8PrivateKeyPem(password, pbe);
        if (_composite != null) return _composite.ExportEncryptedPkcs8PrivateKeyPem(password, pbe);
        throw new InvalidOperationException("Post-quantum key has no algorithm.");
    }

    public X509SignatureGenerator CreateSignatureGenerator()
    {
        if (_mlDsa != null) return X509SignatureGenerator.CreateForMLDsa(_mlDsa);
        if (_slhDsa != null) return X509SignatureGenerator.CreateForSlhDsa(_slhDsa);
        if (_composite != null) return X509SignatureGenerator.CreateForCompositeMLDsa(_composite);
        throw new InvalidOperationException("ML-KEM cannot sign a certificate.");
    }

    public void Dispose()
    {
        _mlDsa?.Dispose();
        _slhDsa?.Dispose();
        _mlKem?.Dispose();
        _composite?.Dispose();
    }

    /// <summary>
    /// Signature generator for a certificate that already holds a PQC private key.
    /// The returned key must stay alive until <c>CertificateRequest.Create</c> returns.
    /// </summary>
    public static (X509SignatureGenerator Generator, IDisposable Key)? SignatureGeneratorFor(X509Certificate2 certificate)
    {
        if (certificate.GetMLDsaPrivateKey() is { } ml)
            return (X509SignatureGenerator.CreateForMLDsa(ml), ml);
        if (certificate.GetSlhDsaPrivateKey() is { } slh)
            return (X509SignatureGenerator.CreateForSlhDsa(slh), slh);
        if (certificate.GetCompositeMLDsaPrivateKey() is { } composite)
            return (X509SignatureGenerator.CreateForCompositeMLDsa(composite), composite);
        return null;
    }

    private static MLDsaAlgorithm MlDsaAlgorithm(string id) => id switch
    {
        "ML-DSA-44" => MLDsaAlgorithm.MLDsa44,
        "ML-DSA-65" => MLDsaAlgorithm.MLDsa65,
        "ML-DSA-87" => MLDsaAlgorithm.MLDsa87,
        _ => throw new ArgumentException($"Unknown ML-DSA parameter set '{id}'.")
    };

    private static MLKemAlgorithm KemAlgorithm(string id) => id switch
    {
        "ML-KEM-512" => MLKemAlgorithm.MLKem512,
        "ML-KEM-768" => MLKemAlgorithm.MLKem768,
        "ML-KEM-1024" => MLKemAlgorithm.MLKem1024,
        _ => throw new ArgumentException($"Unknown ML-KEM parameter set '{id}'.")
    };

    private static SlhDsaAlgorithm SlhAlgorithm(string id) => id switch
    {
        "SLH-DSA-SHA2-128s" => SlhDsaAlgorithm.SlhDsaSha2_128s,
        "SLH-DSA-SHA2-128f" => SlhDsaAlgorithm.SlhDsaSha2_128f,
        "SLH-DSA-SHA2-192s" => SlhDsaAlgorithm.SlhDsaSha2_192s,
        "SLH-DSA-SHA2-192f" => SlhDsaAlgorithm.SlhDsaSha2_192f,
        "SLH-DSA-SHA2-256s" => SlhDsaAlgorithm.SlhDsaSha2_256s,
        "SLH-DSA-SHA2-256f" => SlhDsaAlgorithm.SlhDsaSha2_256f,
        "SLH-DSA-SHAKE-128s" => SlhDsaAlgorithm.SlhDsaShake128s,
        "SLH-DSA-SHAKE-128f" => SlhDsaAlgorithm.SlhDsaShake128f,
        "SLH-DSA-SHAKE-192s" => SlhDsaAlgorithm.SlhDsaShake192s,
        "SLH-DSA-SHAKE-192f" => SlhDsaAlgorithm.SlhDsaShake192f,
        "SLH-DSA-SHAKE-256s" => SlhDsaAlgorithm.SlhDsaShake256s,
        "SLH-DSA-SHAKE-256f" => SlhDsaAlgorithm.SlhDsaShake256f,
        _ => throw new ArgumentException($"Unknown SLH-DSA parameter set '{id}'.")
    };

    private static CompositeMLDsaAlgorithm CompositeAlgorithm(string id) => id switch
    {
        "MLDSA44-RSA2048-PSS-SHA256" => CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pss,
        "MLDSA44-RSA2048-PKCS15-SHA256" => CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pkcs15,
        "MLDSA44-Ed25519-SHA512" => CompositeMLDsaAlgorithm.MLDsa44WithEd25519,
        "MLDSA44-ECDSA-P256-SHA256" => CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256,
        "MLDSA65-RSA3072-PSS-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss,
        "MLDSA65-RSA3072-PKCS15-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pkcs15,
        "MLDSA65-RSA4096-PSS-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pss,
        "MLDSA65-RSA4096-PKCS15-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithRSA4096Pkcs15,
        "MLDSA65-ECDSA-P256-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
        "MLDSA65-ECDSA-P384-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP384,
        "MLDSA65-ECDSA-brainpoolP256r1-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithECDsaBrainpoolP256r1,
        "MLDSA65-Ed25519-SHA512" => CompositeMLDsaAlgorithm.MLDsa65WithEd25519,
        "MLDSA87-ECDSA-P384-SHA512" => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384,
        "MLDSA87-ECDSA-brainpoolP384r1-SHA512" => CompositeMLDsaAlgorithm.MLDsa87WithECDsaBrainpoolP384r1,
        "MLDSA87-ECDSA-P521-SHA512" => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521,
        "MLDSA87-Ed448-SHAKE256" => CompositeMLDsaAlgorithm.MLDsa87WithEd448,
        "MLDSA87-RSA3072-PSS-SHA512" => CompositeMLDsaAlgorithm.MLDsa87WithRSA3072Pss,
        "MLDSA87-RSA4096-PSS-SHA512" => CompositeMLDsaAlgorithm.MLDsa87WithRSA4096Pss,
        _ => throw new ArgumentException($"Unknown composite ML-DSA algorithm '{id}'.")
    };
}
