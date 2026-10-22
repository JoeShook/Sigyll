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
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Sigyll.Common.Services.Pqc;

namespace Sigyll.Common.Services;

/// <summary>
/// Writes every PKCS#12 file Sigyll produces: AES-256-CBC with PBKDF2-HMAC-SHA256
/// (100,000 iterations) for the key and certificates, and an HMAC-SHA256 MAC.
/// <c>X509Certificate2.Export(Pkcs12)</c> writes 3DES/SHA-1 with 2,000 iterations, and
/// <c>CopyWithPrivateKey(MLKem)</c> is not supported on Windows, so this builds the
/// file from the certificate and the encrypted PKCS#8 key directly.
/// </summary>
public static class Pkcs12Writer
{
    public const int Iterations = 100_000;

    public static readonly PbeParameters Pbe =
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Iterations);

    /// <summary>Leaf with its private key attached, plus optional chain certificates.</summary>
    public static byte[] Write(X509Certificate2 leafWithKey, string password, IEnumerable<X509Certificate2>? chain = null)
    {
        if (!leafWithKey.HasPrivateKey)
            throw new ArgumentException("The certificate has no private key.", nameof(leafWithKey));

        return Build(leafWithKey, ExportEncryptedKey(leafWithKey, password), password, chain);
    }

    /// <summary>Leaf plus a separately held post-quantum key (the only way to write ML-KEM on Windows).</summary>
    public static byte[] Write(X509Certificate2 leaf, PqcKeyPair key, string password, IEnumerable<X509Certificate2>? chain = null) =>
        Build(leaf, key.ExportEncryptedPkcs8(password, Pbe), password, chain);

    /// <summary>
    /// Re-encrypts an existing PKCS#12 under <see cref="Pbe"/>, optionally with a new password and
    /// extra certificates. The key is copied as PKCS#8 without loading it into a platform key,
    /// so it works for every algorithm, ML-KEM included.
    /// </summary>
    public static byte[] Rewrap(byte[] pfx, string password, string? newPassword = null, IEnumerable<X509Certificate2>? extraCerts = null)
    {
        newPassword ??= password;
        var certs = new Pkcs12SafeContents();
        var keys = new Pkcs12SafeContents();
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var bag in ReadBags(pfx, password))
        {
            switch (bag)
            {
                case Pkcs12CertBag certBag when certBag.IsX509Certificate:
                    using (var cert = certBag.GetCertificate())
                    {
                        if (!thumbprints.Add(cert.Thumbprint)) continue;
                        CopyAttributes(bag, certs.AddCertificate(cert));
                    }
                    break;
                case Pkcs12ShroudedKeyBag shrouded:
                {
                    var info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, shrouded.EncryptedPkcs8PrivateKey, out _);
                    var rewrapped = new Pkcs12ShroudedKeyBag(info.Encrypt(newPassword, Pbe));
                    CopyAttributes(bag, rewrapped);
                    keys.AddSafeBag(rewrapped);
                    break;
                }
                case Pkcs12KeyBag plain:
                {
                    var info = Pkcs8PrivateKeyInfo.Decode(plain.Pkcs8PrivateKey, out _);
                    var rewrapped = new Pkcs12ShroudedKeyBag(info.Encrypt(newPassword, Pbe));
                    CopyAttributes(bag, rewrapped);
                    keys.AddSafeBag(rewrapped);
                    break;
                }
            }
        }

        foreach (var extra in extraCerts ?? [])
        {
            if (thumbprints.Add(extra.Thumbprint))
                certs.AddCertificate(extra);
        }

        return Seal(certs, keys, newPassword);
    }

    /// <summary>
    /// The first private key in a PKCS#12, as unencrypted PKCS#8. Callers must clear it after use.
    /// Windows cannot hand back an ML-KEM key from a loaded .pfx, so ML-KEM keys are read this way.
    /// </summary>
    public static byte[] ReadPkcs8(byte[] pfx, string password)
    {
        foreach (var bag in ReadBags(pfx, password))
        {
            switch (bag)
            {
                case Pkcs12ShroudedKeyBag shrouded:
                    return Pkcs8PrivateKeyInfo.DecryptAndDecode(password, shrouded.EncryptedPkcs8PrivateKey, out _).Encode();
                case Pkcs12KeyBag plain:
                    return plain.Pkcs8PrivateKey.ToArray();
            }
        }

        throw new CryptographicException("The PKCS#12 holds no private key.");
    }

    private static byte[] Build(X509Certificate2 leaf, byte[] encryptedPkcs8, string password, IEnumerable<X509Certificate2>? chain)
    {
        var localKeyId = new Pkcs9LocalKeyId(leaf.GetCertHash());

        var certs = new Pkcs12SafeContents();
        certs.AddCertificate(leaf).Attributes.Add(localKeyId);
        foreach (var c in chain ?? [])
        {
            if (!string.Equals(c.Thumbprint, leaf.Thumbprint, StringComparison.OrdinalIgnoreCase))
                certs.AddCertificate(c);
        }

        var keys = new Pkcs12SafeContents();
        var keyBag = new Pkcs12ShroudedKeyBag(encryptedPkcs8);
        keyBag.Attributes.Add(localKeyId);
        keys.AddSafeBag(keyBag);

        return Seal(certs, keys, password);
    }

    private static byte[] Seal(Pkcs12SafeContents certs, Pkcs12SafeContents keys, string password)
    {
        var builder = new Pkcs12Builder();
        builder.AddSafeContentsEncrypted(certs, password, Pbe);
        builder.AddSafeContentsUnencrypted(keys); // the key bag is already shrouded
        builder.SealWithMac(password, HashAlgorithmName.SHA256, Iterations);
        return builder.Encode();
    }

    private static IEnumerable<Pkcs12SafeBag> ReadBags(byte[] pfx, string password)
    {
        var info = Pkcs12Info.Decode(pfx, out _);
        if (info.IntegrityMode == Pkcs12IntegrityMode.Password && !info.VerifyMac(password))
            throw new CryptographicException("The PKCS#12 password is incorrect.");

        foreach (var safe in info.AuthenticatedSafe)
        {
            if (safe.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
                safe.Decrypt(password);

            foreach (var bag in safe.GetBags())
                yield return bag;
        }
    }

    private static byte[] ExportEncryptedKey(X509Certificate2 cert, string password)
    {
        using (var rsa = cert.GetRSAPrivateKey())
            if (rsa != null) return rsa.ExportEncryptedPkcs8PrivateKey(password, Pbe);
        using (var ecdsa = cert.GetECDsaPrivateKey())
            if (ecdsa != null) return ecdsa.ExportEncryptedPkcs8PrivateKey(password, Pbe);
        using (var pqc = PqcKeyPair.FromCertificate(cert))
            if (pqc != null) return pqc.ExportEncryptedPkcs8(password, Pbe);

        throw new NotSupportedException($"Cannot export the private key of '{cert.Subject}' ({cert.GetKeyAlgorithm()}).");
    }

    private static void CopyAttributes(Pkcs12SafeBag from, Pkcs12SafeBag to)
    {
        foreach (var attribute in from.Attributes)
            foreach (var value in attribute.Values)
                to.Attributes.Add(value);
    }
}
