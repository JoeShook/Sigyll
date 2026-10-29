#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Components.Account;

namespace Sigyll.Auth.Tests;

public class RecoveryCodeTests
{
    private const string Email = "operator@sigyll.test";

    [Theory]
    [InlineData("ABCDE-12345")]
    [InlineData("abcde-12345")]
    [InlineData("abcde12345")]
    [InlineData("ABCDE 12345")]
    [InlineData(" abcde - 12345 ")]
    [InlineData("AbCdE12345")]
    public void TypedOrPastedCodes_BecomeTheIssuedForm(string typed) =>
        RecoveryCodes.Normalize(typed).ShouldBe("ABCDE-12345");

    [Theory]
    [InlineData("abc", "ABC")]
    [InlineData("abcde-123456", "ABCDE123456")]
    [InlineData("", "")]
    public void InputOfTheWrongLength_IsNotGivenADash(string typed, string expected) =>
        RecoveryCodes.Normalize(typed).ShouldBe(expected);

    [Fact]
    public async Task ACode_SignsInOnce_ThenIsRefused()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);
        string code;
        using (var setup = identity.Request())
            code = (await setup.Users.GenerateNewTwoFactorRecoveryCodesAsync(await setup.UserAsync(Email), 10))!.First();

        var typed = code.Replace("-", "").ToLowerInvariant();

        (await SignInWithRecoveryCodeAsync(identity, typed)).Succeeded.ShouldBeTrue();
        using (var check = identity.Request())
            (await check.Users.CountRecoveryCodesAsync(await check.UserAsync(Email))).ShouldBe(9);

        (await SignInWithRecoveryCodeAsync(identity, typed)).Succeeded.ShouldBeFalse();
    }

    [Fact]
    public async Task ARecoveryCode_IsOnlyAcceptedAfterThePassword()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);
        string code;
        using (var setup = identity.Request())
            code = (await setup.Users.GenerateNewTwoFactorRecoveryCodesAsync(await setup.UserAsync(Email), 10))!.First();

        using var request = identity.Request();
        (await request.SignIn.TwoFactorRecoveryCodeSignInAsync(code)).Succeeded.ShouldBeFalse();
        request.StartedSession.ShouldBeFalse();
    }

    private static async Task<Microsoft.AspNetCore.Identity.SignInResult> SignInWithRecoveryCodeAsync(TestIdentity identity, string typed)
    {
        using var password = identity.Request();
        (await password.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.RequiresTwoFactor.ShouldBeTrue();

        using var recovery = identity.Request(password);
        var result = await recovery.SignIn.TwoFactorRecoveryCodeSignInAsync(RecoveryCodes.Normalize(typed));
        recovery.StartedSession.ShouldBe(result.Succeeded);
        return result;
    }
}
