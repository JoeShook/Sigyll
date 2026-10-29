#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Auth.Tests;

/// <summary>Failed passwords and codes lock an account (Auth:Session: 5 in a row, for 15 minutes, by default).</summary>
public class LockoutTests
{
    private const string Email = "operator@sigyll.test";

    [Fact]
    public async Task FiveWrongPasswords_LockTheAccountForFifteenMinutes()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);

        // The same wrong password each time: repeats count too.
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            using var request = identity.Request();
            var result = (await request.OperatorSignIn.PasswordAsync(Email, "Wrong-password-1")).Result;
            result.IsLockedOut.ShouldBeFalse();
            result.Succeeded.ShouldBeFalse();
        }

        using var fifth = identity.Request();
        (await fifth.OperatorSignIn.PasswordAsync(Email, "Wrong-password-1")).Result.IsLockedOut.ShouldBeTrue();

        var end = await fifth.Users.GetLockoutEndDateAsync(await fifth.UserAsync(Email));
        end.ShouldNotBeNull();
        end.Value.ShouldBeInRange(DateTimeOffset.UtcNow.AddMinutes(14), DateTimeOffset.UtcNow.AddMinutes(15));
    }

    [Fact]
    public async Task ALockedAccount_RefusesTheCorrectPassword_UntilTheLockEnds()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);
        await FailAsync(identity, times: 5);

        using (var locked = identity.Request())
        {
            (await locked.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.IsLockedOut.ShouldBeTrue();
            locked.StartedSession.ShouldBeFalse();
        }

        // Fifteen minutes later.
        using (var request = identity.Request())
            await request.Users.SetLockoutEndDateAsync(await request.UserAsync(Email), DateTimeOffset.UtcNow.AddSeconds(-1));

        using var later = identity.Request();
        (await later.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.Succeeded.ShouldBeTrue();
        later.StartedSession.ShouldBeTrue();
    }

    [Fact]
    public async Task ASuccessfulSignIn_ResetsTheCount()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);
        await FailAsync(identity, times: 4);

        using (var request = identity.Request())
            (await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.Succeeded.ShouldBeTrue();

        using var check = identity.Request();
        (await check.Users.GetAccessFailedCountAsync(await check.UserAsync(Email))).ShouldBe(0);

        // So four more failures don't lock it.
        await FailAsync(identity, times: 4);
        using var after = identity.Request();
        (await after.Users.IsLockedOutAsync(await after.UserAsync(Email))).ShouldBeFalse();
    }

    [Fact]
    public async Task WrongAuthenticatorCodes_CountTowardsLockout()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);

        using var password = identity.Request();
        (await password.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.RequiresTwoFactor.ShouldBeTrue();

        Microsoft.AspNetCore.Identity.SignInResult result = default!;
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            using var code = identity.Request(password);
            result = await code.SignIn.TwoFactorAuthenticatorSignInAsync("000000", isPersistent: false, rememberClient: false);
            code.StartedSession.ShouldBeFalse();
        }

        result.IsLockedOut.ShouldBeTrue();
    }

    [Fact]
    public async Task TheLimitsComeFromConfiguration()
    {
        await using var identity = new TestIdentity(settings: new()
        {
            ["Auth:Session:LockoutAttempts"] = "3",
            ["Auth:Session:LockoutDuration"] = "01:00:00",
        });
        await identity.CreateOperatorAsync(Email);
        await FailAsync(identity, times: 3);

        using var request = identity.Request();
        var user = await request.UserAsync(Email);
        (await request.Users.IsLockedOutAsync(user)).ShouldBeTrue();
        (await request.Users.GetLockoutEndDateAsync(user))!.Value
            .ShouldBeInRange(DateTimeOffset.UtcNow.AddMinutes(59), DateTimeOffset.UtcNow.AddMinutes(60));
    }

    private static async Task FailAsync(TestIdentity identity, int times)
    {
        for (var i = 0; i < times; i++)
        {
            using var request = identity.Request();
            (await request.OperatorSignIn.PasswordAsync(Email, "Wrong-password-1")).Result.Succeeded.ShouldBeFalse();
        }
    }
}
