#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Sigyll.Common.Services;

/// <summary>
/// National Provider Identifier (NPI) handling for Subject Alternative Names.
///
/// An NPI is ten digits; the last is a Luhn (ISO/IEC 7812) check digit computed over the
/// first nine digits prefixed with the card-issuer constant <c>80840</c>. In a certificate it is
/// carried as an otherName whose type-id is <c>2.16.840.1.113883.4.6</c> and whose value is a
/// UTF8String holding the ten digits, as the DirectTrust certificate profiles allow for a
/// verified organization or individual covered entity.
/// </summary>
public static class NpiNumber
{
    /// <summary>otherName type-id for an NPI (HL7 OID registry: National Provider Identifier).</summary>
    public const string OtherNameOid = "2.16.840.1.113883.4.6";

    /// <summary>Card-issuer prefix the NPI check digit is computed with.</summary>
    private const string LuhnPrefix = "80840";

    /// <summary>
    /// True when <paramref name="value"/> is exactly ten ASCII digits with a valid check digit.
    /// No trimming or separators are accepted; callers trim first.
    /// </summary>
    public static bool IsValid(string? value) => value is { Length: 10 } && Validate(value) is null;

    /// <summary>
    /// Returns an error message for an invalid NPI, or null when <paramref name="value"/> is valid.
    /// </summary>
    public static string? Validate(string? value)
    {
        var npi = value?.Trim() ?? string.Empty;

        if (npi.Length != 10 || !npi.All(c => c is >= '0' and <= '9'))
            return $"NPI SAN '{value}' must be exactly 10 digits.";

        if (!LuhnIsValid(LuhnPrefix + npi))
            return $"NPI SAN '{value}' has an invalid check digit.";

        return null;
    }

    /// <summary>Builds the otherName GeneralName carrying <paramref name="npi"/>.</summary>
    public static GeneralName ToGeneralName(string npi) =>
        new(GeneralName.OtherName, new DerSequence(
            new DerObjectIdentifier(OtherNameOid),
            new DerTaggedObject(true, 0, new DerUtf8String(npi))));

    /// <summary>
    /// Reads the NPI from an otherName GeneralName. Returns false when the name is not an
    /// otherName, its type-id is not the NPI OID, or the value is not a string.
    /// </summary>
    public static bool TryRead(GeneralName name, out string npi)
    {
        npi = string.Empty;
        if (name.TagNo != GeneralName.OtherName) return false;

        try
        {
            var (oid, value) = ReadOtherName(name);
            if (oid != OtherNameOid || value is not IAsn1String text) return false;
            npi = text.GetString();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Splits an otherName into its type-id and the (explicitly tagged) value.
    /// </summary>
    internal static (string Oid, Asn1Encodable? Value) ReadOtherName(GeneralName name)
    {
        var seq = Asn1Sequence.GetInstance(name.Name);
        var oid = DerObjectIdentifier.GetInstance(seq[0]).Id;
        Asn1Encodable? value = null;
        if (seq.Count > 1)
        {
            var tagged = Asn1TaggedObject.GetInstance(seq[1]);
            value = tagged.GetExplicitBaseObject();
        }
        return (oid, value);
    }

    private static bool LuhnIsValid(string digits)
    {
        var sum = 0;
        var doubleIt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (doubleIt)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }
}
