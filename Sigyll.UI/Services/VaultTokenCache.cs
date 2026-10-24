#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.UI.Services;

/// <summary>
/// The Vault token an operator pasted to export to Vault, kept for this Blazor circuit only: cleared when they
/// disconnect or refresh, or when Vault refuses it. Never persisted or shared across users.
/// </summary>
public class VaultTokenCache
{
    public string? Token { get; private set; }

    public void Save(string token) => Token = token.Trim();

    public void Clear() => Token = null;
}
