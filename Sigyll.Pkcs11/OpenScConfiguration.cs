#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Pkcs11;

/// <summary>
/// OpenSC looks up card profiles (the files that tell it how to create keys) from a directory baked in at build
/// time, which on Windows is <c>C:\Program Files\OpenSC Project\OpenSC\profiles</c>. A copy of the library that
/// lives anywhere else cannot generate keys until <c>OPENSC_CONF</c> points <c>profile_dir</c> at the
/// <c>profiles</c> folder shipped beside that copy.
/// </summary>
internal static class OpenScConfiguration
{
    /// <summary>
    /// When <paramref name="libraryPath"/> is OpenSC's PKCS #11 library (a <c>pkcs11</c> directory with
    /// <c>profiles</c> next to it) and the process has no <c>OPENSC_CONF</c> yet, point OpenSC at those profiles.
    /// An existing <c>OPENSC_CONF</c> is left alone. Other PKCS #11 libraries are ignored.
    /// </summary>
    public static void UseProfilesBesideLibrary(string libraryPath)
    {
        if (!OperatingSystem.IsWindows() || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OPENSC_CONF")))
            return;

        var libraryDirectory = Path.GetDirectoryName(libraryPath);
        if (string.IsNullOrEmpty(libraryDirectory))
            return;

        var profiles = Path.GetFullPath(Path.Combine(libraryDirectory, "..", "profiles"));
        if (!File.Exists(Path.Combine(profiles, "pkcs15.profile")))
            return;

        var configuration = Path.Combine(Path.GetTempPath(), "sigyll-opensc.conf");
        File.WriteAllText(configuration,
            "app default {\n\tprofile_dir = \"" + profiles.Replace('\\', '/') + "\";\n}\n");
        Environment.SetEnvironmentVariable("OPENSC_CONF", configuration);
    }
}
