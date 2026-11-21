#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Contracts;

/// <summary>
/// Request from the RA portal to the CA core to revoke certificates whose exchange purpose authorization was withdrawn
/// (<c>POST /api/ra/revoke-by-exchange-purpose</c>). The CA revokes each listed certificate with reason
/// <c>privilegeWithdrawn</c> only when one of its URI SANs carries <see cref="ExchangePurpose"/>, records each
/// revocation in its audit trail and publishes a new CRL for every issuing CA involved.
/// </summary>
public class RevocationApiRequest
{
    /// <summary>Serial numbers (hex, as returned on issuance) of the certificates to revoke.</summary>
    public List<string> SerialNumbers { get; set; } = [];

    /// <summary>The exchange purpose code (e.g. <c>T-TRTMNT</c>) whose authorization was withdrawn.</summary>
    public string ExchangePurpose { get; set; } = string.Empty;

    /// <summary>The subscriber (organization) the certificates were issued to, as the portal names it, for audit.</summary>
    public string SubscriberRef { get; set; } = string.Empty;

    /// <summary>The RA user who ordered the revocation, for audit.</summary>
    public string RequestedBy { get; set; } = string.Empty;
}

/// <summary>Result of <see cref="RevocationApiRequest"/>.</summary>
public class RevocationApiResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>Serial numbers the CA revoked.</summary>
    public List<string> Revoked { get; set; } = [];

    /// <summary>Serial numbers the CA left alone, each with the reason (already revoked, unknown, no matching SAN).</summary>
    public Dictionary<string, string> Skipped { get; set; } = [];

    /// <summary>Problems publishing the new CRLs; the revocations themselves stand.</summary>
    public List<string> CrlErrors { get; set; } = [];

    public static RevocationApiResult Failure(string error) => new() { Success = false, Error = error };
}
