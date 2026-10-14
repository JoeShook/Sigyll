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
/// Verifies an X.509 certificate or CRL signature when BouncyCastle does not recognise the
/// post-quantum OID. The signature covers the exact tbsCertificate / tbsCertList bytes.
/// </summary>
public static class PqcCertificateVerifier
{
    private static readonly byte[] EmptyContext = [];

    /// <summary>
    /// Returns true/false when <paramref name="issuerDer"/> has an ML-DSA, SLH-DSA or composite
    /// public key. Returns null when the issuer is classical, so the caller keeps its own path.
    /// </summary>
    public static bool? TryVerify(byte[] subjectDer, byte[] issuerDer)
    {
        using var issuer = X509CertificateLoader.LoadCertificate(issuerDer);
        if (!HasSignatureKey(issuer)) return null;
        if (!TrySliceSigned(subjectDer, out var tbs, out var signature)) return false;
        return Verify(issuer, tbs, signature);
    }

    private static bool HasSignatureKey(X509Certificate2 issuer)
    {
        using var ml = issuer.GetMLDsaPublicKey();
        if (ml != null) return true;
        using var slh = issuer.GetSlhDsaPublicKey();
        if (slh != null) return true;
        using var composite = issuer.GetCompositeMLDsaPublicKey();
        return composite != null;
    }

    private static bool Verify(X509Certificate2 issuer, ReadOnlySpan<byte> tbs, byte[] signature)
    {
        var message = tbs.ToArray();
        using (var ml = issuer.GetMLDsaPublicKey())
        {
            if (ml != null) return ml.VerifyData(message, signature, EmptyContext);
        }

        using (var slh = issuer.GetSlhDsaPublicKey())
        {
            if (slh != null) return slh.VerifyData(message, signature, EmptyContext);
        }

        using var composite = issuer.GetCompositeMLDsaPublicKey();
        return composite != null && composite.VerifyData(message, signature, EmptyContext);
    }

    /// <summary>
    /// Splits a DER Certificate or CertificateList into the encoded TBS (the signed bytes)
    /// and the raw signature value.
    /// </summary>
    internal static bool TrySliceSigned(ReadOnlySpan<byte> der, out ReadOnlySpan<byte> tbs, out byte[] signature)
    {
        tbs = default;
        signature = [];
        try
        {
            var sequence = ReadTlv(der, 0);
            var cursor = sequence.ContentOffset;
            var tbsTlv = ReadTlv(der, cursor);
            tbs = der.Slice(cursor, tbsTlv.TotalLength);
            cursor += tbsTlv.TotalLength;
            cursor += ReadTlv(der, cursor).TotalLength;
            var bitString = ReadTlv(der, cursor);
            if (bitString.ContentLength < 2) return false;
            signature = der.Slice(bitString.ContentOffset + 1, bitString.ContentLength - 1).ToArray();
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private readonly record struct Tlv(int ContentOffset, int ContentLength, int TotalLength);

    private static Tlv ReadTlv(ReadOnlySpan<byte> der, int offset)
    {
        var start = offset;
        if ((uint)offset >= (uint)der.Length)
            throw new CryptographicException("Truncated DER.");
        offset++; // tag
        var length = ReadLength(der, ref offset);
        if (offset + length > der.Length)
            throw new CryptographicException("DER value overruns the buffer.");
        return new Tlv(offset, length, offset + length - start);
    }

    private static int ReadLength(ReadOnlySpan<byte> der, ref int offset)
    {
        var first = der[offset++];
        if ((first & 0x80) == 0) return first;
        var count = first & 0x7F;
        if (count is 0 or > 4)
            throw new CryptographicException("Unsupported DER length.");
        var length = 0;
        for (var i = 0; i < count; i++)
            length = (length << 8) | der[offset++];
        return length;
    }
}
