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

/// <summary>An operator can't remove their last second factor.</summary>
public class FactorRemovalTests
{
    private const string Email = "operator@sigyll.test";

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    public async Task TheAuthenticatorApp_CanBeTurnedOff_OnlyIfAPasskeyRemains(int passkeys, bool allowed)
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true, passkeys: passkeys);

        using var request = identity.Request();
        (await OperatorMfa.CanTurnOffAuthenticatorAsync(request.Users, await request.UserAsync(Email))).ShouldBe(allowed);
    }

    [Theory]
    [InlineData(false, 1, false)]
    [InlineData(false, 2, true)]
    [InlineData(true, 1, true)]
    public async Task APasskey_CanBeRemoved_OnlyIfAnotherFactorRemains(bool authenticator, int passkeys, bool allowed)
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator, passkeys);

        using var request = identity.Request();
        (await OperatorMfa.CanRemovePasskeyAsync(request.Users, await request.UserAsync(Email))).ShouldBe(allowed);
    }

    [Theory]
    [InlineData(false, 0, false)]
    [InlineData(true, 0, true)]
    [InlineData(false, 1, true)]
    public async Task HasSecondFactor_CountsTheAuthenticatorAppAndPasskeys(bool authenticator, int passkeys, bool expected)
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator, passkeys);

        using var request = identity.Request();
        (await OperatorMfa.HasSecondFactorAsync(request.Users, await request.UserAsync(Email))).ShouldBe(expected);
    }
}
