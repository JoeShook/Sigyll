#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sigyll.ServiceDefaults;

/// <summary>
/// Repairs credential JSON that authenticators such as LastPass produce. WebAuthn's credential JSON type requires
/// <c>clientExtensionResults</c>, and Identity rejects the credential when the member is absent. When no extension
/// was requested, <c>getClientExtensionResults()</c> is an empty object; some authenticators omit the member
/// instead, and <c>JSON.stringify</c> also drops it when <c>toJSON()</c> sets it to <c>undefined</c>.
/// </summary>
public static class PasskeyCredentialJson
{
    /// <summary>
    /// Returns <paramref name="credentialJson"/> with <c>clientExtensionResults</c> set to an empty object when the
    /// root is a credential object and the member is missing or null. Anything else is returned unchanged, including
    /// a map the authenticator actually sent.
    /// </summary>
    public static string EnsureClientExtensionResults(string credentialJson)
    {
        if (string.IsNullOrEmpty(credentialJson))
            return credentialJson;

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(credentialJson);
        }
        catch (JsonException)
        {
            return credentialJson;
        }

        if (root is not JsonObject credential || credential["clientExtensionResults"] is not null)
            return credentialJson;

        credential["clientExtensionResults"] = new JsonObject();
        return credential.ToJsonString();
    }
}
