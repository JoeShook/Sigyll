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
/// Result returned by the CA core's internal issuance API (<c>POST /api/ra/issue</c>).
/// </summary>
public class IssuanceApiResult
{
    public bool Success { get; set; }

    /// <summary>Populated on failure with a human-readable reason.</summary>
    public string? Error { get; set; }

    /// <summary>The issued end-entity certificate, PEM-encoded.</summary>
    public string? CertificatePem { get; set; }

    /// <summary>The issuing chain (issuer up to root), PEM-encoded, in order.</summary>
    public string? ChainPem { get; set; }

    public string? SerialNumber { get; set; }
    public string? Thumbprint { get; set; }

    public static IssuanceApiResult Failure(string error) =>
        new() { Success = false, Error = error };
}
