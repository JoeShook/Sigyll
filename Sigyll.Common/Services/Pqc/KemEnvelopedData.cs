#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Sigyll.Common.Services.Pqc;

/// <summary>
/// CMS EnvelopedData addressed to an ML-KEM certificate: one KEMRecipientInfo (RFC 9629)
/// with HKDF-SHA256 and AES-256 key wrap, content in AES-256-CBC. This is the encryption
/// half of a post-quantum Direct (S/MIME) message; .NET's EnvelopedCms has no KEM recipients.
/// </summary>
public static class KemEnvelopedData
{
    private const string EnvelopedDataOid = "1.2.840.113549.1.7.3";
    private const string DataOid = "1.2.840.113549.1.7.1";
    private const string OriKemOid = "1.2.840.113549.1.9.16.13.3";
    private const string HkdfSha256Oid = "1.2.840.113549.1.9.16.3.28";
    private const string Aes256WrapOid = "2.16.840.1.101.3.4.1.45";
    private const string Aes256CbcOid = "2.16.840.1.101.3.4.1.42";
    private const int KekLength = 32;

    private static readonly Asn1Tag OriTag = new(TagClass.ContextSpecific, 4, isConstructed: true);
    private static readonly Asn1Tag ExplicitZero = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag ImplicitZero = new(TagClass.ContextSpecific, 0);

    /// <summary>Encrypts <paramref name="content"/> to the ML-KEM public key in <paramref name="recipient"/>.</summary>
    public static byte[] Encrypt(byte[] content, X509Certificate2 recipient)
    {
        using var kem = recipient.GetMLKemPublicKey()
            ?? throw new ArgumentException("The recipient certificate does not hold an ML-KEM key.", nameof(recipient));

        kem.Encapsulate(out var kemCiphertext, out var sharedSecret);
        var cek = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        try
        {
            var encryptedKey = Wrap(true, DeriveKek(sharedSecret), cek);

            byte[] encryptedContent;
            using (var aes = Aes.Create())
            {
                aes.Key = cek;
                encryptedContent = aes.EncryptCbc(content, iv);
            }

            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(EnvelopedDataOid);
                using (writer.PushSequence(ExplicitZero))
                using (writer.PushSequence())
                {
                    writer.WriteInteger(3); // ori present
                    using (writer.PushSetOf())
                    using (writer.PushSequence(OriTag))
                    {
                        writer.WriteObjectIdentifier(OriKemOid);
                        using (writer.PushSequence()) // KEMRecipientInfo
                        {
                            writer.WriteInteger(0);
                            WriteIssuerAndSerial(writer, recipient);
                            WriteAlgorithm(writer, recipient.PublicKey.Oid.Value!);
                            writer.WriteOctetString(kemCiphertext);
                            WriteAlgorithm(writer, HkdfSha256Oid);
                            writer.WriteInteger(KekLength);
                            WriteAlgorithm(writer, Aes256WrapOid);
                            writer.WriteOctetString(encryptedKey);
                        }
                    }

                    using (writer.PushSequence()) // EncryptedContentInfo
                    {
                        writer.WriteObjectIdentifier(DataOid);
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(Aes256CbcOid);
                            writer.WriteOctetString(iv);
                        }
                        writer.WriteOctetString(encryptedContent, ImplicitZero);
                    }
                }
            }

            return writer.Encode();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    /// <summary>
    /// Decrypts EnvelopedData with the ML-KEM private key that belongs to <paramref name="recipient"/>.
    /// Throws <see cref="CryptographicException"/> when no KEMRecipientInfo names that certificate.
    /// </summary>
    public static byte[] Decrypt(byte[] envelopedData, X509Certificate2 recipient, MLKem privateKey)
    {
        var contentInfo = new AsnReader(envelopedData, AsnEncodingRules.BER).ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != EnvelopedDataOid)
            throw new CryptographicException("Not CMS EnvelopedData.");

        var enveloped = contentInfo.ReadSequence(ExplicitZero).ReadSequence();
        enveloped.ReadInteger();
        if (enveloped.PeekTag().HasSameClassAndValue(ExplicitZero))
            enveloped.ReadEncodedValue(); // originatorInfo

        byte[]? cek = null;
        var recipients = enveloped.ReadSetOf();
        while (recipients.HasData && cek == null)
        {
            if (!recipients.PeekTag().HasSameClassAndValue(OriTag))
            {
                recipients.ReadEncodedValue();
                continue;
            }

            var ori = recipients.ReadSequence(OriTag);
            if (ori.ReadObjectIdentifier() != OriKemOid)
                continue;

            var kemri = ori.ReadSequence();
            kemri.ReadInteger();
            if (!IsIssuerAndSerialOf(kemri.ReadEncodedValue(), recipient))
                continue;

            ReadAlgorithm(kemri); // kem: the key itself fixes the parameter set
            var kemCiphertext = kemri.ReadOctetString();
            if (ReadAlgorithm(kemri) != HkdfSha256Oid)
                throw new CryptographicException("Only HKDF-SHA256 is supported.");
            if (!kemri.TryReadInt32(out var kekLength) || kekLength != KekLength)
                throw new CryptographicException("Only a 32-byte KEK is supported.");
            if (kemri.PeekTag().HasSameClassAndValue(ExplicitZero))
                throw new CryptographicException("User keying material is not supported.");
            if (ReadAlgorithm(kemri) != Aes256WrapOid)
                throw new CryptographicException("Only AES-256 key wrap is supported.");
            var encryptedKey = kemri.ReadOctetString();

            var sharedSecret = privateKey.Decapsulate(kemCiphertext);
            try
            {
                cek = Wrap(false, DeriveKek(sharedSecret), encryptedKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }
        }

        if (cek == null)
            throw new CryptographicException("No KEMRecipientInfo is addressed to this certificate.");

        try
        {
            var encryptedContentInfo = enveloped.ReadSequence();
            encryptedContentInfo.ReadObjectIdentifier();
            var algorithm = encryptedContentInfo.ReadSequence();
            if (algorithm.ReadObjectIdentifier() != Aes256CbcOid)
                throw new CryptographicException("Only AES-256-CBC content is supported.");
            var iv = algorithm.ReadOctetString();
            var ciphertext = encryptedContentInfo.ReadOctetString(ImplicitZero);

            using var aes = Aes.Create();
            aes.Key = cek;
            return aes.DecryptCbc(ciphertext, iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    // RFC 9629 §5: KEK = HKDF(IKM = shared secret, info = DER(CMSORIforKEMOtherInfo), L = kekLength).
    private static byte[] DeriveKek(byte[] sharedSecret)
    {
        var info = new AsnWriter(AsnEncodingRules.DER);
        using (info.PushSequence())
        {
            WriteAlgorithm(info, Aes256WrapOid);
            info.WriteInteger(KekLength);
        }

        return HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, KekLength, salt: [], info: info.Encode());
    }

    // RFC 3394 AES key wrap; .NET only ships the padded RFC 5649 variant.
    private static byte[] Wrap(bool wrap, byte[] kek, byte[] input)
    {
        try
        {
            var engine = new AesWrapEngine();
            engine.Init(wrap, new KeyParameter(kek));
            return wrap ? engine.Wrap(input, 0, input.Length) : engine.Unwrap(input, 0, input.Length);
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException ex)
        {
            throw new CryptographicException("The content-encryption key did not unwrap.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private static void WriteIssuerAndSerial(AsnWriter writer, X509Certificate2 certificate)
    {
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(certificate.IssuerName.RawData);
            writer.WriteInteger(certificate.SerialNumberBytes.Span);
        }
    }

    private static bool IsIssuerAndSerialOf(ReadOnlyMemory<byte> encoded, X509Certificate2 certificate)
    {
        var expected = new AsnWriter(AsnEncodingRules.DER);
        WriteIssuerAndSerial(expected, certificate);
        return encoded.Span.SequenceEqual(expected.Encode());
    }

    private static void WriteAlgorithm(AsnWriter writer, string oid)
    {
        using (writer.PushSequence())
            writer.WriteObjectIdentifier(oid);
    }

    private static string ReadAlgorithm(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
            algorithm.ReadEncodedValue(); // parameters: none expected for these algorithms
        return oid;
    }
}
