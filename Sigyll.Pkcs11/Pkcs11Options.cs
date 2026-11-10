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

/// <summary>Configuration for signing with keys on a PKCS #11 token (section <c>Pkcs11</c>).</summary>
public class Pkcs11Options
{
    /// <summary>
    /// Path to the token vendor's PKCS #11 library, loaded into Sigyll's process: for example
    /// <c>/usr/lib/softhsm/libsofthsm2.so</c> for SoftHSM, or the HSM client's library.
    /// </summary>
    public string LibraryPath { get; set; } = string.Empty;

    /// <summary>Label of the token (partition) that holds Sigyll's keys.</summary>
    public string TokenLabel { get; set; } = string.Empty;

    /// <summary>
    /// The token's user PIN. Supply it from a secret store (Vault, user secrets, the deployment's secret
    /// mechanism); never put it in appsettings.json.
    /// </summary>
    public string UserPin { get; set; } = string.Empty;

    /// <summary>
    /// Set true only when the token is a FIPS 140-3 validated hardware security module. Keys are then recorded as
    /// HSM-held, which a trust domain requiring HSM-held CA keys accepts. SoftHSM is never recorded as hardware,
    /// whatever this says.
    /// </summary>
    public bool HardwareProtected { get; set; }
}
