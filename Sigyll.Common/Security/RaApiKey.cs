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
using System.Text;

namespace Sigyll.Common.Security;

/// <summary>
/// The shared key the RA portal may present to the CA's RA API instead of a client certificate.
/// </summary>
public static class RaApiKey
{
    /// <summary>The key the repository's Development settings use; anywhere else it is refused.</summary>
    public const string DevelopmentPlaceholder = "dev-ra-key-change-me";

    /// <summary>Shortest key accepted outside Development.</summary>
    public const int MinimumLength = 32;

    /// <summary>
    /// Why the configured key can't be used, or null if it can. No key at all is allowed: the RA API then
    /// refuses every call. Outside Development the placeholder and short keys are refused, so a deployment
    /// can't run with a key anyone who has read the repository knows.
    /// </summary>
    public static string? Problem(string? configuredKey, bool isDevelopment)
    {
        if (string.IsNullOrEmpty(configuredKey) || isDevelopment)
            return null;
        if (configuredKey == DevelopmentPlaceholder)
            return "Ra:ApiKey is the published development placeholder. Configure a random key of at least "
                 + $"{MinimumLength} characters, or set Ra:UseMtls, or remove Ra:ApiKey to turn the RA API off.";
        if (configuredKey.Length < MinimumLength)
            return $"Ra:ApiKey is shorter than {MinimumLength} characters. Configure a longer random key, "
                 + "or set Ra:UseMtls, or remove Ra:ApiKey to turn the RA API off.";
        return null;
    }

    /// <summary>
    /// Whether the presented key is the configured one, in time that doesn't depend on where they differ.
    /// Both are hashed first so the comparison doesn't reveal the key's length either.
    /// </summary>
    public static bool Matches(string? presentedKey, string? configuredKey)
    {
        if (string.IsNullOrEmpty(presentedKey) || string.IsNullOrEmpty(configuredKey))
            return false;
        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(presentedKey)),
            SHA256.HashData(Encoding.UTF8.GetBytes(configuredKey)));
    }
}
