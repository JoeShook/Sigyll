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

/// <summary>
/// A passkey returned after its prompt lapsed (it timed out, or Sigyll restarted in between) is refused without an
/// error page, so the operator can try again.
/// </summary>
public class PasskeyPromptTests
{
    private const string Email = "operator@sigyll.test";

    [Fact]
    public async Task SignInWithoutAPendingPrompt_IsRefused_NotAnError()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        using var request = identity.Request();
        (await request.OperatorSignIn.PasskeyAsync("{}")).ShouldBeNull();
        request.StartedSession.ShouldBeFalse();
    }

    [Fact]
    public async Task AddingAPasskeyWithoutAPendingPrompt_IsRefused_NotAnError()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);

        using var request = identity.Request();
        (await request.OperatorSignIn.AttestPasskeyAsync("{}")).ShouldBeNull();
        (await request.Users.GetPasskeysAsync(await request.UserAsync(Email))).ShouldBeEmpty();
    }
}
