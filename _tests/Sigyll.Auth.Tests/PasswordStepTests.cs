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

/// <summary>The password step of sign-in (OperatorSignIn): a password alone never starts a session for an operator who has a second factor.</summary>
public class PasswordStepTests
{
    private const string Email = "operator@sigyll.test";

    [Fact]
    public async Task AuthenticatorOperator_CorrectPassword_GoesOnToTheCodeStep_WithoutASession()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);

        step.Result.RequiresTwoFactor.ShouldBeTrue();
        step.PasskeyRequired.ShouldBeFalse();
        request.StartedSession.ShouldBeFalse();
    }

    [Fact]
    public async Task PasskeyOperator_CorrectPassword_DoesNotSignIn_AndAsksForThePasskey()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);

        step.PasskeyRequired.ShouldBeTrue();
        request.StartedSession.ShouldBeFalse();
        request.SetCookies.ShouldBeEmpty();
    }

    [Fact]
    public async Task OperatorWithBothFactors_IsAskedForTheCode()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true, passkeys: 1);

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);

        step.Result.RequiresTwoFactor.ShouldBeTrue();
        step.PasskeyRequired.ShouldBeFalse();
        request.StartedSession.ShouldBeFalse();
    }

    [Fact]
    public async Task PasskeyOperator_WrongPasswords_CountTowardsLockout()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        for (var attempt = 1; attempt <= 4; attempt++)
        {
            using var request = identity.Request();
            var step = await request.OperatorSignIn.PasswordAsync(Email, "wrong");
            step.Result.Succeeded.ShouldBeFalse();
            step.PasskeyRequired.ShouldBeFalse();
        }

        using (var fifth = identity.Request())
            (await fifth.OperatorSignIn.PasswordAsync(Email, "wrong")).Result.IsLockedOut.ShouldBeTrue();

        using var afterwards = identity.Request();
        var correct = await afterwards.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);
        correct.Result.IsLockedOut.ShouldBeTrue();
        correct.PasskeyRequired.ShouldBeFalse();
    }

    [Fact]
    public async Task OperatorWithoutAFactorYet_SignsIn_SoTheyCanSetOneUp()
    {
        // The enrollment middleware then keeps them on the setup page (MfaEnrollmentTests).
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);

        step.Result.Succeeded.ShouldBeTrue();
        request.StartedSession.ShouldBeTrue();
    }

    [Fact]
    public async Task UnknownOperator_Fails()
    {
        await using var identity = new TestIdentity();

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync("nobody@sigyll.test", TestIdentity.Password);

        step.Result.Succeeded.ShouldBeFalse();
        step.PasskeyRequired.ShouldBeFalse();
        request.StartedSession.ShouldBeFalse();
    }

    [Fact]
    public async Task InDevelopment_WithMfaTurnedOff_APasskeyOperatorsPasswordSignsIn()
    {
        await using var identity = new TestIdentity("Development", new() { ["Auth:RequireMfa"] = "false" });
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);

        step.Result.Succeeded.ShouldBeTrue();
        step.PasskeyRequired.ShouldBeFalse();
    }

    [Fact]
    public async Task OutsideDevelopment_MfaCanNotBeTurnedOff()
    {
        await using var identity = new TestIdentity("Production", new() { ["Auth:RequireMfa"] = "false" });
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        using var request = identity.Request();
        var step = await request.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password);

        step.PasskeyRequired.ShouldBeTrue();
        request.StartedSession.ShouldBeFalse();
    }
}
