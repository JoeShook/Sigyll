#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Buffers.Binary;
using System.Security.Cryptography;
using Sigyll.Common.Services.Audit;
using Sigyll.Components.Account;

namespace Sigyll.Auth.Tests;

/// <summary>Every sign-in attempt, lockout and sign-out lands in the audit trail (OperatorSignInManager).</summary>
public class SignInAuditTests
{
    private const string Email = "operator@sigyll.test";

    [Fact]
    public async Task PasswordAndAuthenticatorCode_RecordOneSignIn()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);

        using var password = identity.Request();
        (await password.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.RequiresTwoFactor.ShouldBeTrue();
        string key;
        using (var setup = identity.Request())
            key = (await setup.Users.GetAuthenticatorKeyAsync(await setup.UserAsync(Email)))!;

        using var code = identity.Request(password);
        (await code.SignIn.TwoFactorAuthenticatorSignInAsync(Totp(key), isPersistent: false, rememberClient: false))
            .Succeeded.ShouldBeTrue();

        // The correct password alone is not a sign-in; the one event is the completed sign-in.
        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignedIn);
        e.Succeeded.ShouldBeTrue();
        e.Actor.ShouldBe(Email);
        e.ActorIsSystem.ShouldBeFalse();
        e.EntityType.ShouldBe("Operator");
        e.EntityName.ShouldBe(Email);
        e.Detail.ShouldBe("Password and authenticator app; from 192.0.2.10");
    }

    [Fact]
    public async Task AWrongPassword_IsRecordedAsAFailure()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);

        using (var request = identity.Request())
            await request.OperatorSignIn.PasswordAsync(Email, "Wrong-password-1");

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Succeeded.ShouldBeFalse();
        e.Actor.ShouldBe(Email);
        e.Detail.ShouldBe("Wrong password; from 192.0.2.10");
    }

    [Fact]
    public async Task APasskeyOperatorsWrongPassword_IsRecordedAsAFailure()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        using (var request = identity.Request())
            await request.OperatorSignIn.PasswordAsync(Email, "Wrong-password-1");
        // Their correct password only leads to the passkey prompt: nothing to record yet.
        using (var request = identity.Request())
            (await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).PasskeyRequired.ShouldBeTrue();

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Detail.ShouldStartWith("Wrong password");
    }

    [Theory]
    [InlineData("nobody@sigyll.test", "nobody@sigyll.test")]
    [InlineData("Correct-horse-battery-1", null)]
    [InlineData("two words@sigyll.test", null)]
    public async Task AnUnknownAccount_IsRecorded_KeepingOnlyANameThatLooksLikeAnAccount(string typed, string? kept)
    {
        await using var identity = new TestIdentity();

        using (var request = identity.Request())
            (await request.OperatorSignIn.PasswordAsync(typed, "Whatever-1")).Result.Succeeded.ShouldBeFalse();

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Actor.ShouldBe(kept ?? "(unknown account)");
        e.EntityName.ShouldBe(kept);
        e.Detail.ShouldBe("Unknown account; from 192.0.2.10");
    }

    [Fact]
    public async Task TheFailureThatLocksTheAccount_IsFollowedByALockout_ThenLockedAttemptsAreRecorded()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            using var request = identity.Request();
            await request.OperatorSignIn.PasswordAsync(Email, "Wrong-password-1");
        }
        using (var request = identity.Request())
            (await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.IsLockedOut.ShouldBeTrue();

        var events = await identity.AuditEventsAsync();
        events.Select(e => e.Action).ShouldBe(
        [
            .. Enumerable.Repeat(AuditActions.OperatorSignInFailed, 5),
            AuditActions.OperatorLockedOut,
            AuditActions.OperatorSignInFailed,
        ]);
        events[5].Detail.ShouldStartWith("After 5 failed attempts; locked until ");
        events[6].Detail.ShouldBe("Account locked; from 192.0.2.10");
    }

    [Fact]
    public async Task AWrongAuthenticatorCode_IsRecorded()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);

        using var password = identity.Request();
        await password.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);
        using (var code = identity.Request(password))
            await code.SignIn.TwoFactorAuthenticatorSignInAsync("000000", isPersistent: false, rememberClient: false);

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Actor.ShouldBe(Email);
        e.Detail.ShouldBe("Wrong authenticator code; from 192.0.2.10");
    }

    [Fact]
    public async Task ARecoveryCodeSignIn_SaysHowManyCodesAreLeft()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);
        string recoveryCode;
        using (var setup = identity.Request())
            recoveryCode = (await setup.Users.GenerateNewTwoFactorRecoveryCodesAsync(await setup.UserAsync(Email), 10))!.First();

        using var password = identity.Request();
        await password.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);
        using (var wrong = identity.Request(password))
            (await wrong.SignIn.TwoFactorRecoveryCodeSignInAsync("AAAAA-BBBBB")).Succeeded.ShouldBeFalse();
        using (var right = identity.Request(password))
            (await right.SignIn.TwoFactorRecoveryCodeSignInAsync(recoveryCode)).Succeeded.ShouldBeTrue();

        var events = await identity.AuditEventsAsync();
        events.Count.ShouldBe(2);
        events[0].Action.ShouldBe(AuditActions.OperatorSignInFailed);
        events[0].Detail.ShouldBe("Wrong recovery code; from 192.0.2.10");
        events[1].Action.ShouldBe(AuditActions.OperatorSignedIn);
        events[1].Detail.ShouldBe("Password and recovery code (9 left); from 192.0.2.10");
    }

    [Fact]
    public async Task AnExpiredPasskeyPrompt_IsRecorded()
    {
        await using var identity = new TestIdentity();

        using (var request = identity.Request())
            (await request.OperatorSignIn.PasskeyAsync("{}")).ShouldBeNull();

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Actor.ShouldBe("(unknown account)");
        e.Detail.ShouldBe("Passkey prompt expired; from 192.0.2.10");
    }

    [Fact]
    public async Task APasswordOnlySignIn_WhereDevelopmentAllowsIt_IsRecorded()
    {
        await using var identity = new TestIdentity("Development", new() { ["Auth:RequireMfa"] = "false" });
        await identity.CreateOperatorAsync(Email);

        using (var request = identity.Request())
            (await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.Succeeded.ShouldBeTrue();

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignedIn);
        e.Detail.ShouldBe("Password only (no second factor); from 192.0.2.10");
    }

    [Fact]
    public async Task SigningOut_IsRecorded_OnlyForASignedInOperator()
    {
        await using var identity = new TestIdentity();

        using (var anonymous = identity.Request())
            await anonymous.SignIn.SignOutAsync();
        (await identity.AuditEventsAsync()).ShouldBeEmpty();

        using (var request = identity.Request())
        {
            request.Http.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, Email)], "Identity.Application"));
            await request.SignIn.SignOutAsync();
        }

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignedOut);
        e.Actor.ShouldBe(Email);
        e.Detail.ShouldBe("Signed out; from 192.0.2.10");
    }

    [Fact]
    public async Task TheSignInManager_IsTheAuditingOne()
    {
        await using var identity = new TestIdentity();
        using var request = identity.Request();
        request.SignIn.ShouldBeOfType<OperatorSignInManager>();
    }

    /// <summary>The authenticator app's current code for <paramref name="base32Key"/> (RFC 6238: SHA-1, 30 s, 6 digits).</summary>
    private static string Totp(string base32Key)
    {
        var key = Base32(base32Key);
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
        var hash = HMACSHA1.HashData(key, counter);
        var offset = hash[^1] & 0x0f;
        var value = (BinaryPrimitives.ReadInt32BigEndian(hash.AsSpan(offset)) & 0x7fffffff) % 1_000_000;
        return value.ToString("D6");
    }

    private static byte[] Base32(string text)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in text.TrimEnd('=').ToUpperInvariant())
        {
            buffer = (buffer << 5) | alphabet.IndexOf(c);
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return [.. bytes];
    }
}
