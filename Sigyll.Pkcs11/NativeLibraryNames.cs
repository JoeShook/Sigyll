#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Reflection;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Sigyll.Pkcs11;

/// <summary>
/// Pkcs11Interop loads a vendor's PKCS #11 library through <c>dlopen</c> from a library it names "libdl". Since glibc
/// 2.34 (Ubuntu 22.04 and later, so the .NET 10 images) only <c>libdl.so.2</c> is installed unless developer packages
/// are, so on Linux "libdl" is resolved to that instead of adding packages to the runtime image.
/// </summary>
public static class NativeLibraryNames
{
    private static int _registered;

    public static void Register()
    {
        if (!OperatingSystem.IsLinux() || Interlocked.Exchange(ref _registered, 1) == 1)
            return;

        try
        {
            NativeLibrary.SetDllImportResolver(typeof(Pkcs11InteropFactories).Assembly, Resolve);
        }
        catch (InvalidOperationException)
        {
            // Something else already set a resolver for Pkcs11Interop; leave it in charge.
        }
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == "libdl" && NativeLibrary.TryLoad("libdl.so.2", assembly, searchPath, out var handle))
            return handle;
        return IntPtr.Zero; // fall back to the runtime's normal lookup
    }
}
