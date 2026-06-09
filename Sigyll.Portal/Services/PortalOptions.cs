#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Portal.Services;

/// <summary>
/// Portal configuration (config section "Portal"): how to reach the CA core's internal RA API and
/// the passkey relying-party domain.
/// </summary>
public class PortalOptions
{
    /// <summary>Base URL of the CA core (e.g. https://localhost:7200).</summary>
    public string CaBaseUrl { get; set; } = string.Empty;

    /// <summary>When true, authenticate to the CA with a client certificate (mTLS). When false,
    /// use the dev API-key header. Always true in production.</summary>
    public bool UseMtls { get; set; }

    /// <summary>Dev fallback shared secret sent as <c>X-RA-ApiKey</c> to the CA.</summary>
    public string? RaApiKey { get; set; }

    public PasskeyOptions Passkey { get; set; } = new();

    public class PasskeyOptions
    {
        /// <summary>Relying Party ID for passkeys (e.g. "localhost"). Pinned explicitly for a CA.</summary>
        public string? ServerDomain { get; set; }
    }
}
