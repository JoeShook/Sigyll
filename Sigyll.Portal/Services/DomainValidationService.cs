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
using Sigyll.Portal.Data.Entities;

namespace Sigyll.Portal.Services;

/// <summary>
/// http-01 domain-control validation. The requester serves the challenge's key authorization at
/// <c>http://&lt;identifier&gt;/.well-known/sigyll-challenge/&lt;token&gt;</c>; this service generates
/// challenges and verifies them by fetching that URL. The path shape is intentionally ACME-style so
/// the Phase 12b ACME server can reuse the model. (dns-01 / tls-alpn-01 are deferred to 12b.)
/// </summary>
public class DomainValidationService(IHttpClientFactory httpClientFactory, ILogger<DomainValidationService> logger)
{
    public const string WellKnownPath = ".well-known/sigyll-challenge";

    /// <summary>Creates a pending challenge for one DNS identifier (caller persists it).</summary>
    public DomainValidationChallenge CreateChallenge(string identifier)
    {
        var token = Base64Url(RandomNumberGenerator.GetBytes(32));
        var secret = Base64Url(RandomNumberGenerator.GetBytes(32));
        return new DomainValidationChallenge
        {
            Identifier = identifier,
            Token = token,
            KeyAuthorization = $"{token}.{secret}",
            Status = DomainValidationStatus.Pending,
        };
    }

    /// <summary>The URL the requester must serve the key authorization at.</summary>
    public static string ChallengeUrl(DomainValidationChallenge c) =>
        $"http://{c.Identifier}/{WellKnownPath}/{c.Token}";

    /// <summary>
    /// Fetches the challenge URL and compares the body to the expected key authorization. Mutates
    /// the challenge (Status/Attempts/VerifiedAt); the caller persists. Returns true if validated.
    /// </summary>
    public async Task<bool> VerifyAsync(DomainValidationChallenge challenge, CancellationToken ct = default)
    {
        challenge.Attempts++;
        var url = ChallengeUrl(challenge);
        try
        {
            using var client = httpClientFactory.CreateClient("dv");
            client.Timeout = TimeSpan.FromSeconds(10);
            var body = (await client.GetStringAsync(url, ct)).Trim();
            if (string.Equals(body, challenge.KeyAuthorization, StringComparison.Ordinal))
            {
                challenge.Status = DomainValidationStatus.Valid;
                challenge.VerifiedAt = DateTime.UtcNow;
                return true;
            }

            logger.LogInformation("http-01 mismatch for {Identifier} at {Url}", challenge.Identifier, url);
            challenge.Status = DomainValidationStatus.Invalid;
            return false;
        }
        catch (Exception ex)
        {
            logger.LogInformation(ex, "http-01 fetch failed for {Identifier} at {Url}", challenge.Identifier, url);
            challenge.Status = DomainValidationStatus.Invalid;
            return false;
        }
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
