#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace Sigyll.Pkcs11;

/// <summary>
/// Keeps a PKCS #11 library in memory for the life of the process. Pkcs11Interop unloads the library whenever its
/// wrapper is disposed, and unloading is not safe for every library: a thread that used it can still have clean-up
/// registered in it, and crashes the process when it later exits into code that is gone (seen with SoftHSM on macOS
/// and with a Native AOT library on Linux). Holding one extra reference turns that unload into a no-op, so the
/// library can be finalised and initialised again in place.
/// </summary>
internal static class LoadedLibraries
{
    private static readonly ConcurrentDictionary<string, IntPtr> Held = new(StringComparer.Ordinal);

    /// <summary>Takes a reference to the library that is never given back. Does nothing the second time.</summary>
    public static void KeepLoaded(string libraryPath)
    {
        var path = Path.GetFullPath(libraryPath);
        Held.GetOrAdd(path, static p => NativeLibrary.TryLoad(p, out var handle) ? handle : IntPtr.Zero);
    }
}
