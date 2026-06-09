#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Portal.Data.Entities;

/// <summary>
/// An http-01 domain-control challenge for one DNS identifier on an auto-issue request. The
/// requester serves <see cref="KeyAuthorization"/> at
/// <c>http://&lt;identifier&gt;/.well-known/sigyll-challenge/&lt;Token&gt;</c>; the portal fetches and
/// verifies it. http-01 shape is intentionally ACME-compatible for the Phase 12b ACME server.
/// </summary>
public class DomainValidationChallenge
{
    public int Id { get; set; }

    public int RequestId { get; set; }
    public CertificateRequest Request { get; set; } = null!;

    /// <summary>The DNS name being validated.</summary>
    public string Identifier { get; set; } = string.Empty;

    /// <summary>Random challenge token (the URL path segment).</summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>Expected content served at the challenge URL.</summary>
    public string KeyAuthorization { get; set; } = string.Empty;

    public DomainValidationStatus Status { get; set; } = DomainValidationStatus.Pending;
    public int Attempts { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? VerifiedAt { get; set; }
}

/// <summary>State of a domain-control challenge.</summary>
public enum DomainValidationStatus
{
    Pending = 0,
    Valid = 1,
    Invalid = 2,
}
