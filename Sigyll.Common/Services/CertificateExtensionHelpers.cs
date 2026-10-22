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
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sigyll.Common.Services;

/// <summary>
/// Static helpers for building X.509 certificate extensions that .NET doesn't natively support.
/// Extracted from Udap.PKI.Generator for reuse by Sigyll and CLI tools.
/// </summary>
public static class CertificateExtensionHelpers
{
    /// <summary>
    /// Adds an Authority Key Identifier (AKI) extension (OID 2.5.29.35)
    /// derived from the issuing CA's Subject Key Identifier.
    /// </summary>
    public static void AddAuthorityKeyIdentifier(
        X509Certificate2 issuerCert,
        CertificateRequest request)
    {
        var issuerSubjectKey = issuerCert.Extensions["2.5.29.14"]?.RawData;
        if (issuerSubjectKey == null || issuerSubjectKey.Length < 4)
            return;

        var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
        var authorityKeyIdentifier = new byte[segment.Count + 4];
        authorityKeyIdentifier[0] = 0x30; // SEQUENCE
        authorityKeyIdentifier[1] = 0x16;
        authorityKeyIdentifier[2] = 0x80; // [0] implicit KeyIdentifier
        authorityKeyIdentifier[3] = 0x14;
        segment.CopyTo(authorityKeyIdentifier, 4);

        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
    }

    /// <summary>
    /// Adds an Authority Key Identifier extension to a list of extensions (for remote signing path).
    /// </summary>
    public static void AddAuthorityKeyIdentifierToList(
        X509Certificate2 issuerCert,
        List<X509Extension> extensions)
    {
        var issuerSubjectKey = issuerCert.Extensions["2.5.29.14"]?.RawData;
        if (issuerSubjectKey == null || issuerSubjectKey.Length < 4)
            return;

        var segment = new ArraySegment<byte>(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
        var authorityKeyIdentifier = new byte[segment.Count + 4];
        authorityKeyIdentifier[0] = 0x30; // SEQUENCE
        authorityKeyIdentifier[1] = 0x16;
        authorityKeyIdentifier[2] = 0x80; // [0] implicit KeyIdentifier
        authorityKeyIdentifier[3] = 0x14;
        segment.CopyTo(authorityKeyIdentifier, 4);

        extensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
    }

    /// <summary>
    /// Builds a CRL Distribution Points extension (OID 2.5.29.31) containing one or more distribution points.
    /// </summary>
    public static X509Extension MakeCdp(IReadOnlyList<string> urls)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
        {
            foreach (var url in urls)
            {
                using (writer.PushSequence()) // DistributionPoint ::= SEQUENCE
                {
                    // distributionPoint [0] EXPLICIT
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        // fullName [0] IMPLICIT GeneralNames
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                        {
                            // uniformResourceIdentifier [6] IMPLICIT IA5String
                            writer.WriteCharacterString(
                                UniversalTagNumber.IA5String, url,
                                new Asn1Tag(TagClass.ContextSpecific, 6));
                        }
                    }
                }
            }
        }

        return new X509Extension("2.5.29.31", writer.Encode(), critical: false);
    }

    /// <summary>
    /// Builds a CRL Distribution Points extension for a single URL.
    /// </summary>
    public static X509Extension MakeCdp(string url) => MakeCdp(new[] { url });

    /// <summary>
    /// Builds an Authority Information Access (AIA) extension (OID 1.3.6.1.5.5.7.1.1)
    /// with one or more CA Issuers access descriptions.
    /// </summary>
    public static X509Extension BuildAiaExtension(IReadOnlyList<Uri> caIssuerUris, bool critical = false)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
        {
            foreach (var uri in caIssuerUris)
            {
                using (writer.PushSequence()) // AccessDescription ::= SEQUENCE
                {
                    writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2"); // CA Issuers
                    writer.WriteCharacterString(
                        UniversalTagNumber.IA5String,
                        uri.AbsoluteUri,
                        new Asn1Tag(TagClass.ContextSpecific, 6));
                }
            }
        }

        return new X509Extension("1.3.6.1.5.5.7.1.1", writer.Encode(), critical);
    }

    /// <summary>
    /// Builds an AIA extension for a single CA Issuer URI.
    /// </summary>
    public static X509Extension BuildAiaExtension(Uri caIssuerUri, bool critical = false) =>
        BuildAiaExtension(new[] { caIssuerUri }, critical);

    /// <summary>id-pe-relatedCert (RFC 9763).</summary>
    public const string RelatedCertificateOid = "1.3.6.1.5.5.7.1.36";

    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// RFC 9763 RelatedCertificate: <c>SEQUENCE { hashAlgorithm, hashValue OCTET STRING }</c>
    /// holding the SHA-256 of the related certificate's DER. Ties a Direct encryption
    /// certificate to its signing partner.
    /// </summary>
    public static X509Extension BuildRelatedCertificate(byte[] relatedCertificateDer)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
                writer.WriteObjectIdentifier(Sha256Oid);
            writer.WriteOctetString(System.Security.Cryptography.SHA256.HashData(relatedCertificateDer));
        }

        return new X509Extension(RelatedCertificateOid, writer.Encode(), critical: false);
    }

    /// <summary>Display text for an RFC 9763 RelatedCertificate extension: the hash algorithm and value.</summary>
    public static string DescribeRelatedCertificate(X509Extension extension)
    {
        try
        {
            var sequence = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            var algorithm = sequence.ReadSequence().ReadObjectIdentifier();
            var hash = sequence.ReadOctetString();
            var name = algorithm == Sha256Oid ? "SHA-256" : algorithm;
            return $"Hash of the related certificate ({name}):\n{Convert.ToHexString(hash)}";
        }
        catch (AsnContentException)
        {
            return Convert.ToHexString(extension.RawData);
        }
    }

    /// <summary>
    /// True when <paramref name="certificate"/> carries an RFC 9763 RelatedCertificate
    /// extension whose SHA-256 hash matches <paramref name="relatedCertificateDer"/>.
    /// </summary>
    public static bool IsRelatedTo(X509Certificate2 certificate, byte[] relatedCertificateDer)
    {
        var extension = certificate.Extensions[RelatedCertificateOid];
        if (extension == null)
            return false;

        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        var algorithm = sequence.ReadSequence().ReadObjectIdentifier();
        var hash = sequence.ReadOctetString();
        return algorithm == Sha256Oid
            && hash.AsSpan().SequenceEqual(System.Security.Cryptography.SHA256.HashData(relatedCertificateDer));
    }
}
