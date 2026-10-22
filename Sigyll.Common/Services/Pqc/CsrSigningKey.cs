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
/// A key that can sign a PKCS#10 request: RSA, ECDSA, or a post-quantum signature key.
/// ML-KEM is rejected here because a CSR signature is proof of possession.
/// </summary>
public sealed class CsrSigningKey : IDisposable
{
    private readonly AsymmetricAlgorithm? _classical;
    private readonly PqcKeyPair? _pqc;

    private CsrSigningKey(AsymmetricAlgorithm? classical, PqcKeyPair? pqc)
    {
        _classical = classical;
        _pqc = pqc;
    }

    public static CsrSigningKey Generate(string algorithm, int keySize)
    {
        var canonical = PqcAlgorithms.Canonicalize(algorithm, keySize);
        if (canonical != null)
        {
            if (PqcAlgorithms.IsKem(canonical))
                throw new InvalidOperationException(
                    "ML-KEM cannot sign a CSR. Issue an ML-KEM certificate from a profile instead, or choose ML-DSA, SLH-DSA, or composite ML-DSA.");
            return new CsrSigningKey(null, PqcKeyPair.Generate(canonical));
        }

        return new CsrSigningKey(CreateClassical(algorithm, keySize), null);
    }

    public static CsrSigningKey FromCertificate(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPrivateKey() is { } rsa)
            return new CsrSigningKey(rsa, null);
        if (certificate.GetECDsaPrivateKey() is { } ecdsa)
            return new CsrSigningKey(ecdsa, null);
        var pqc = PqcKeyPair.FromCertificate(certificate);
        if (pqc is { CanSign: true })
            return new CsrSigningKey(null, pqc);
        pqc?.Dispose();
        throw new InvalidOperationException("Unsupported private key. RSA, ECDSA, ML-DSA, SLH-DSA and composite ML-DSA can sign a CSR.");
    }

    public static CsrSigningKey ImportEncryptedPkcs8(string algorithm, int keySize, string pem, string password)
    {
        var canonical = PqcAlgorithms.Canonicalize(algorithm, keySize);
        if (canonical != null)
            return new CsrSigningKey(null, PqcKeyPair.ImportEncryptedPkcs8(canonical, pem, password));

        if (algorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromEncryptedPem(pem, password);
            return new CsrSigningKey(ecdsa, null);
        }

        var rsa = RSA.Create();
        rsa.ImportFromEncryptedPem(pem, password);
        return new CsrSigningKey(rsa, null);
    }

    public (string Algorithm, int KeySize) Describe()
    {
        if (_pqc != null) return (_pqc.AlgorithmId, _pqc.KeySize);
        return _classical switch
        {
            RSA rsa => ("RSA", rsa.KeySize),
            ECDsa ecdsa => ("ECDSA", ecdsa.KeySize),
            _ => ("Unknown", 0)
        };
    }

    public CertificateRequest CreateRequest(X500DistinguishedName subject)
    {
        if (_pqc != null) return _pqc.CreateCertificateRequest(subject);
        return _classical switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new InvalidOperationException("Unsupported key algorithm.")
        };
    }

    public X509Certificate2 AttachPrivateKey(X509Certificate2 certificate)
    {
        if (_pqc != null) return _pqc.CopyWithPrivateKey(certificate);
        return _classical switch
        {
            RSA rsa => certificate.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
            _ => throw new InvalidOperationException("Unsupported key algorithm.")
        };
    }

    public string ExportEncryptedPkcs8Pem(string password, PbeParameters pbe)
    {
        if (_pqc != null) return _pqc.ExportEncryptedPkcs8Pem(password, pbe);
        return _classical!.ExportEncryptedPkcs8PrivateKeyPem(password, pbe);
    }

    public void Dispose()
    {
        _classical?.Dispose();
        _pqc?.Dispose();
    }

    private static AsymmetricAlgorithm CreateClassical(string algorithm, int size)
    {
        if (algorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var curve = size switch
            {
                256 => ECCurve.NamedCurves.nistP256,
                384 => ECCurve.NamedCurves.nistP384,
                521 => ECCurve.NamedCurves.nistP521,
                _ => throw new ArgumentException($"Unsupported ECDSA key size {size}; use 256, 384 or 521.")
            };
            return ECDsa.Create(curve);
        }

        if (size is not (2048 or 3072 or 4096))
            throw new ArgumentException($"Unsupported RSA key size {size}; use 2048, 3072 or 4096.");
        return RSA.Create(size);
    }
}
