#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;
using Sigyll.Common.Services.Audit;
using Sigyll.Components.Account;

namespace Sigyll.Auth.Tests;

/// <summary>
/// An operator's changes to their own sign-in security land in the audit trail (OperatorUserManager); changes made
/// by someone else, or by Identity's own bookkeeping, don't.
/// </summary>
public class SecurityChangeAuditTests
{
    private const string Email = "operator@sigyll.test";
    private const string OtherAdmin = "admin@sigyll.test";

    [Fact]
    public async Task TurningTheAuthenticatorOnAndOff_IsRecorded_WithTheRecoveryCodes()
    {
        await using var identity = new TestIdentity();
        var self = await identity.CreateOperatorAsync(Email);

        using (var request = SignedIn(identity, self))
        {
            var user = await request.UserAsync(Email);
            await request.Users.ResetAuthenticatorKeyAsync(user);
            await request.Users.SetTwoFactorEnabledAsync(user, true);
            await request.Users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            await request.Users.SetTwoFactorEnabledAsync(user, true);   // already on: nothing changed
            await OperatorMfa.TurnOffAuthenticatorAsync(request.Users, user);
        }

        (await DetailsAsync(identity)).ShouldBe(
        [
            "Authenticator app key reset",
            "Authenticator app turned on",
            "New recovery codes issued (10)",
            "Authenticator app turned off",
            "Recovery codes revoked (10)",
        ]);
        var events = await identity.AuditEventsAsync();
        events.ShouldAllBe(e => e.Action == AuditActions.OperatorSecurityChanged && e.Actor == Email
                                && e.EntityName == Email && e.Succeeded);
        events.ShouldAllBe(e => e.Detail!.EndsWith("; from 192.0.2.10"));
    }

    [Fact]
    public async Task IssuingNewRecoveryCodes_SaysTheOldOnesWereRevoked()
    {
        await using var identity = new TestIdentity();
        var self = await identity.CreateOperatorAsync(Email, authenticator: true);

        using (var request = SignedIn(identity, self))
        {
            var user = await request.UserAsync(Email);
            await request.Users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            await request.Users.RedeemTwoFactorRecoveryCodeAsync(user,
                (await request.Users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))!.First());
            await request.Users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        }

        (await DetailsAsync(identity)).ShouldBe(
        [
            "New recovery codes issued (10)",
            "New recovery codes issued (10); the 10 unused ones revoked",
            "New recovery codes issued (10); the 9 unused ones revoked",
        ]);
    }

    [Fact]
    public async Task Passkeys_AddedNamedRenamedAndRemoved_AreRecorded_ButNotTheirSignInBookkeeping()
    {
        await using var identity = new TestIdentity();
        var self = await identity.CreateOperatorAsync(Email, authenticator: true);
        var passkey = TestIdentity.Passkey();

        using (var request = SignedIn(identity, self))
        {
            var user = await request.UserAsync(Email);
            await request.Users.AddOrUpdatePasskeyAsync(user, passkey);
            passkey.Name = "iPhone";
            await request.Users.AddOrUpdatePasskeyAsync(user, passkey);
            passkey.Name = "Joe's iPhone";
            await request.Users.AddOrUpdatePasskeyAsync(user, passkey);
            passkey.SignCount = 7;                                     // a sign-in's counter update: not a change
            await request.Users.AddOrUpdatePasskeyAsync(user, passkey);
            await request.Users.RemovePasskeyAsync(user, passkey.CredentialId);
        }

        (await DetailsAsync(identity)).ShouldBe(
        [
            "Passkey added",
            "Passkey named \"iPhone\"",
            "Passkey renamed from \"iPhone\" to \"Joe's iPhone\"",
            "Passkey removed (\"Joe's iPhone\")",
        ]);
    }

    [Fact]
    public async Task PasswordChanges_AreRecorded()
    {
        await using var identity = new TestIdentity();
        var self = await identity.CreateOperatorAsync(Email, authenticator: true);

        using (var request = SignedIn(identity, self))
        {
            var user = await request.UserAsync(Email);
            (await request.Users.ChangePasswordAsync(user, "Wrong-password-1", "New-password-123")).Succeeded.ShouldBeFalse();
            (await request.Users.ChangePasswordAsync(user, TestIdentity.Password, "New-password-123")).Succeeded.ShouldBeTrue();
            await request.Users.RemovePasswordAsync(user);
            await request.Users.AddPasswordAsync(user, TestIdentity.Password);
        }

        // The refused change isn't a change.
        (await DetailsAsync(identity)).ShouldBe(["Password changed", "Password removed", "Password set"]);
    }

    [Fact]
    public async Task ChangesBySomeoneElse_OrSignedOut_AreNotRecordedHere()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true, passkeys: 1);
        var admin = await identity.CreateOperatorAsync(OtherAdmin);

        // An Admin's actions on another operator are recorded by the page or service that performs them.
        using (var request = SignedIn(identity, admin))
        {
            var user = await request.UserAsync(Email);
            await request.Users.SetTwoFactorEnabledAsync(user, false);
            await request.Users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            await request.Users.RemovePasskeyAsync(user, (await request.Users.GetPasskeysAsync(user))[0].CredentialId);
            var token = await request.Users.GeneratePasswordResetTokenAsync(user);
            (await request.Users.ResetPasswordAsync(user, token, "New-password-123")).Succeeded.ShouldBeTrue();
        }
        // Nobody signed in (startup seeding, Identity's own work during sign-in).
        using (var request = identity.Request())
            await request.Users.SetTwoFactorEnabledAsync(await request.UserAsync(Email), true);

        (await identity.AuditEventsAsync()).ShouldBeEmpty();
    }

    [Fact]
    public async Task APasswordResetByEmailedLink_MadeSignedOut_IsRecorded()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);

        using (var request = identity.Request())
        {
            var user = await request.UserAsync(Email);
            var token = await request.Users.GeneratePasswordResetTokenAsync(user);
            (await request.Users.ResetPasswordAsync(user, token, "New-password-123")).Succeeded.ShouldBeTrue();
        }

        var e = (await identity.AuditEventsAsync()).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSecurityChanged);
        e.Detail.ShouldBe("Password reset with an emailed link; from 192.0.2.10");
    }

    [Fact]
    public async Task TheUserManager_IsTheAuditingOne()
    {
        await using var identity = new TestIdentity();
        using var request = identity.Request();
        request.Users.ShouldBeOfType<OperatorUserManager>();
    }

    /// <summary>
    /// A request from <paramref name="user"/>'s signed-in browser. Synchronous on purpose: the request becomes the
    /// current one through an AsyncLocal, which an async helper would set only for itself.
    /// </summary>
    private static TestRequest SignedIn(TestIdentity identity, Sigyll.Data.SigyllUser user)
    {
        var request = identity.Request();
        request.Http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, user.Id), new Claim(ClaimTypes.Name, user.Email!)], "Identity.Application"));
        return request;
    }

    private static async Task<List<string>> DetailsAsync(TestIdentity identity) =>
        [.. (await identity.AuditEventsAsync()).Select(e => e.Detail!.Replace("; from 192.0.2.10", ""))];
}
