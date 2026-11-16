#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;

namespace Sigyll.Common.Services;

/// <summary>
/// How a private key is held when a PKCS #12 file is loaded only to be used and thrown away. On Windows and Linux
/// the key stays in memory (<see cref="X509KeyStorageFlags.EphemeralKeySet"/>), so nothing is written to a key
/// store. macOS does not support that and refuses the load; there the platform's default is used, which keeps the
/// key in a temporary keychain until the certificate is disposed.
/// </summary>
public static class Pkcs12KeyStorage
{
    /// <summary>In memory only where the platform allows it.</summary>
    public static X509KeyStorageFlags InMemory =>
        OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;

    /// <summary><see cref="InMemory"/>, with a key that can be exported again.</summary>
    public static X509KeyStorageFlags InMemoryExportable => InMemory | X509KeyStorageFlags.Exportable;
}
