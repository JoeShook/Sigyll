#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Identity;
using Sigyll.Common.Services.Audit;
using Sigyll.ServiceDefaults;

namespace Sigyll.Auth.Tests;

/// <summary>
/// LastPass posts a passkey whose JSON omits <c>clientExtensionResults</c>. Identity requires that member, so the
/// credential is repaired to an empty map before attestation or assertion. The repair must not turn a non-credential
/// into one, and a prompt that has already lapsed is still refused.
/// </summary>
public class PasskeyCredentialJsonTests
{
    private const string Email = "operator@sigyll.test";

    private const string AttestationWithoutExtensions =
        """{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"AQID","attestationObject":"AQID"}}""";

    private const string AssertionWithoutExtensions =
        """{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"AQID","authenticatorData":"AQID","signature":"AQID"}}""";

    [Fact]
    public void AMissingExtensionsMap_BecomesAnEmptyObject()
    {
        var json = PasskeyCredentialJson.EnsureClientExtensionResults("""{"id":"abc","type":"public-key"}""");
        var root = JsonNode.Parse(json)!.AsObject();
        root["id"]!.GetValue<string>().ShouldBe("abc");
        root["type"]!.GetValue<string>().ShouldBe("public-key");
        root["clientExtensionResults"]!.AsObject().Count.ShouldBe(0);
    }

    [Fact]
    public void ANullExtensionsMap_BecomesAnEmptyObject()
    {
        var json = PasskeyCredentialJson.EnsureClientExtensionResults("""{"id":"abc","clientExtensionResults":null}""");
        JsonNode.Parse(json)!["clientExtensionResults"]!.AsObject().Count.ShouldBe(0);
    }

    [Fact]
    public void AnExtensionsMap_IsLeftUntouched()
    {
        const string json = """{"clientExtensionResults":{"credProps":{"rk":true}},"id":"abc"}""";
        PasskeyCredentialJson.EnsureClientExtensionResults(json).ShouldBe(json);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("null")]
    public void SomethingThatIsNotACredential_IsLeftUntouched(string json) =>
        PasskeyCredentialJson.EnsureClientExtensionResults(json).ShouldBe(json);

    [Fact]
    public async Task AddingAPasskey_AcceptsACredentialThatOmitsClientExtensionResults()
    {
        await using var identity = new TestIdentity();
        var user = await identity.CreateOperatorAsync(Email, authenticator: true);

        using var begun = identity.Request();
        await begun.SignIn.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
        {
            Id = user.Id,
            Name = user.UserName!,
            DisplayName = user.UserName!,
        });

        using var add = identity.Request(begun);
        var result = await add.OperatorSignIn.AttestPasskeyAsync(AttestationWithoutExtensions);
        result.ShouldNotBeNull();
        result.Succeeded.ShouldBeFalse();
        result.Failure.Message.ShouldNotContain("clientExtensionResults");
        (await add.Users.GetPasskeysAsync(await add.UserAsync(Email))).ShouldBeEmpty();
    }

    [Fact]
    public async Task SigningIn_AcceptsACredentialThatOmitsClientExtensionResults()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, passkeys: 1);

        using var begun = identity.Request();
        await begun.SignIn.MakePasskeyRequestOptionsAsync(await begun.UserAsync(Email));

        using var signIn = identity.Request(begun);
        var result = await signIn.OperatorSignIn.PasskeyAsync(AssertionWithoutExtensions);
        result.ShouldNotBeNull();
        result.Succeeded.ShouldBeFalse();
        signIn.StartedSession.ShouldBeFalse();

        var refusal = (await identity.AuditEventsAsync())
            .Single(e => e.Action == AuditActions.OperatorSignInFailed && e.Detail!.Contains("Passkey refused"));
        refusal.Detail.ShouldNotBeNull().ShouldNotContain("clientExtensionResults");
    }
}
