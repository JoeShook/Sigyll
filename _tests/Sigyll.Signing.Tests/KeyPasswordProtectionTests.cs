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
using Shouldly;
using Sigyll.Common.Data;
using Xunit;

namespace Sigyll.Signing.Tests;

// Uses the explicit-key overloads: the process-wide master key is shared with every other test.
public class KeyPasswordProtectionTests
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(KeyPasswordProtection.MasterKeyLength);

    [Fact]
    public void Protect_RoundTrips()
    {
        var stored = KeyPasswordProtection.Protect("p@ss-wörd", Key);

        stored.ShouldStartWith(KeyPasswordProtection.Prefix);
        stored.ShouldNotContain("p@ss");
        KeyPasswordProtection.Unprotect(stored, Key).ShouldBe("p@ss-wörd");
    }

    [Fact]
    public void Protect_UsesAFreshNonceEachTime()
    {
        KeyPasswordProtection.Protect("same", Key).ShouldNotBe(KeyPasswordProtection.Protect("same", Key));
    }

    [Fact]
    public void Unprotect_RejectsAnotherKey()
    {
        var stored = KeyPasswordProtection.Protect("secret", Key);

        Should.Throw<CryptographicException>(() =>
            KeyPasswordProtection.Unprotect(stored, RandomNumberGenerator.GetBytes(KeyPasswordProtection.MasterKeyLength)));
    }

    [Fact]
    public void Unprotect_RejectsTampering()
    {
        var stored = KeyPasswordProtection.Protect("secret", Key);
        var payload = Convert.FromBase64String(stored[KeyPasswordProtection.Prefix.Length..]);
        payload[^1] ^= 0x01;

        Should.Throw<CryptographicException>(() =>
            KeyPasswordProtection.Unprotect(KeyPasswordProtection.Prefix + Convert.ToBase64String(payload), Key));
    }

    [Fact]
    public void Unprotect_LeavesPlainTextAsItIs()
    {
        KeyPasswordProtection.Unprotect("legacy-password").ShouldBe("legacy-password");
        KeyPasswordProtection.IsProtected("legacy-password").ShouldBeFalse();
    }

    [Fact]
    public void ParseMasterKey_RequiresThirtyTwoBytes()
    {
        KeyPasswordProtection.ParseMasterKey(Convert.ToBase64String(Key)).ShouldBe(Key);
        Should.Throw<InvalidOperationException>(() => KeyPasswordProtection.ParseMasterKey(Convert.ToBase64String(new byte[16])));
        Should.Throw<InvalidOperationException>(() => KeyPasswordProtection.ParseMasterKey("not base64!"));
    }
}
