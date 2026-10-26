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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Shouldly;
using Sigyll.Common.Services;

namespace Sigyll.Signing.Tests;

public class DistinguishedNameTextTests
{
    private const string EmailOid = "1.2.840.113549.1.9.1";
    private const string UidOid = "0.9.2342.19200300.100.1.1";

    private const string OpenSslDn =
        "C=US, ST=Minnesota, L=900 2nd Ave South, O=pharmacysystem, OU=CAA, CN=client.user, " +
        "emailAddress=client.user@example.com";

    [Fact]
    public void OpenSslEmailAddress_IsRejectedByDotNetUntilNormalized()
    {
        Should.Throw<CryptographicException>(() => new X500DistinguishedName(OpenSslDn));

        var name = new X500DistinguishedName(DistinguishedNameText.Normalize(OpenSslDn));

        var email = name.EnumerateRelativeDistinguishedNames()
            .Single(r => r.GetSingleElementType().Value == EmailOid);
        email.GetSingleElementValue().ShouldBe("client.user@example.com");
        name.EnumerateRelativeDistinguishedNames().Count().ShouldBe(7);
    }

    [Fact]
    public void EmailAddress_IsEncodedAsIa5String()
    {
        var name = new X500DistinguishedName(DistinguishedNameText.Normalize(OpenSslDn));

        var rdn = name.EnumerateRelativeDistinguishedNames()
            .Single(r => r.GetSingleElementType().Value == EmailOid);
        var value = Asn1Object.FromByteArray(rdn.RawData.ToArray()) as Asn1Set;
        var pair = (Asn1Sequence)value![0];
        pair[1].ShouldBeOfType<DerIA5String>();
    }

    [Fact]
    public void Normalized_ParsesInBouncyCastle()
    {
        var name = new X509Name(DistinguishedNameText.Normalize(OpenSslDn));

        name.GetValueList(X509Name.EmailAddress).Cast<string>().ShouldBe(["client.user@example.com"]);
    }

    [Theory]
    [InlineData("UID=jdoe, CN=x")]
    [InlineData("userId=jdoe, CN=x")]
    public void Uid_BecomesItsOid(string dn)
    {
        var normalized = DistinguishedNameText.Normalize(dn);

        normalized.ShouldBe($"OID.{UidOid}=jdoe, CN=x");
        new X500DistinguishedName(normalized).EnumerateRelativeDistinguishedNames()
            .ShouldContain(r => r.GetSingleElementType().Value == UidOid);
    }

    [Theory]
    [InlineData("CN=x, O=y, C=US")]
    [InlineData("CN=\"emailAddress=a, b\", O=y")]
    [InlineData(@"CN=a\, emailAddress=b, O=y")]
    [InlineData("CN=https://example.org/fhir?x=1, O=My Org")]
    public void ValuesAndOtherNames_AreLeftAlone(string dn)
    {
        DistinguishedNameText.Normalize(dn).ShouldBe(dn);
    }

    [Fact]
    public void LabelsAreCaseInsensitive_AndMultiValuedRdnsAreHandled()
    {
        DistinguishedNameText.Normalize("CN=x+EMAILADDRESS=a@b.c;  emailaddress=d@e.f")
            .ShouldBe("CN=x+E=a@b.c;  E=d@e.f");
    }
}
