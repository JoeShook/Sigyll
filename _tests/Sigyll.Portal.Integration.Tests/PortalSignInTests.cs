#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using Sigyll.Portal.Services;
using Sigyll.Tests;

namespace Sigyll.Portal.Integration.Tests;

/// <summary>
/// Portal sign-in end to end, the way a requester's browser does it: the real pages and forms, cookies and
/// redirects, and the audit trail read back from PostgreSQL. Each test uses its own account.
/// </summary>
[Collection(PortalAppCollection.Name)]
public class PortalSignInTests(PortalApp app)
{
    private const string Login = "/Account/Login";

    [Fact]
    public async Task TheDemoAccounts_DoNotExistOutsideDevelopment()
    {
        (await app.FindUserAsync("admin@sigyll.local")).ShouldBeNull();
        (await app.FindUserAsync("requester@sigyll.local")).ShouldBeNull();

        using var browser = app.Browser();
        var page = await SignInWithPasswordAsync(browser, "admin@sigyll.local", "Passw0rd!");

        page.Html.ShouldContain("Invalid login attempt");
        (await app.AuditEventsAsync("admin@sigyll.local")).ShouldHaveSingleItem().Detail.ShouldStartWith("Unknown account");
    }

    [Fact]
    public async Task APasswordSignIn_ThenSignOut_AreBothAudited()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email);
        using var browser = app.Browser();

        (await SignInWithPasswordAsync(browser, email, PortalApp.Password)).Url.AbsolutePath.ShouldBe("/");
        (await Browser.GetAsync(browser, "/requests")).Url.AbsolutePath.ShouldBe("/requests");   // the session works

        await Browser.PostWithTokenAsync(browser, "/", "/Account/Logout", new Dictionary<string, string> { ["returnUrl"] = "" });
        (await Browser.GetAsync(browser, "/requests")).Url.AbsolutePath.ShouldBe(Login);   // and is over

        var events = await app.AuditEventsAsync(email);
        events.Select(e => e.Action).ShouldBe([PortalAuditActions.SignedIn, PortalAuditActions.SignedOut]);
        events[0].Detail.ShouldStartWith("Password only");
        events[0].Actor.ShouldBe(email);
        events[1].Detail.ShouldStartWith("Signed out");
        events.ShouldAllBe(e => e.OccurredAt > DateTime.UtcNow.AddMinutes(-5));   // stamped by the database
    }

    [Fact]
    public async Task PasswordAndAuthenticatorCode_IsOneAuditedSignIn()
    {
        var email = NewEmail();
        var key = await app.CreateUserAsync(email, authenticator: true);
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email, PortalApp.Password);
        twoFactor.Url.AbsolutePath.ShouldBe("/Account/LoginWith2fa");
        (await app.AuditEventsAsync(email)).ShouldBeEmpty();   // the password alone is not a sign-in

        var home = await Browser.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key!) });

        home.Url.AbsolutePath.ShouldBe("/");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(PortalAuditActions.SignedIn);
        e.Detail.ShouldStartWith("Password and authenticator app");
    }

    [Fact]
    public async Task AWrongPassword_IsRefused_AndAudited()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email);
        using var browser = app.Browser();

        var page = await SignInWithPasswordAsync(browser, email, "Wrong-password-1");

        page.Html.ShouldContain("Invalid login attempt");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(PortalAuditActions.SignInFailed);
        e.Succeeded.ShouldBeFalse();
        e.Detail.ShouldStartWith("Wrong password");
    }

    [Fact]
    public async Task FiveWrongPasswords_LockTheAccount_EvenAgainstTheRightOne()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email);
        using var browser = app.Browser();

        for (var attempt = 1; attempt <= 5; attempt++)
            await SignInWithPasswordAsync(browser, email, "Wrong-password-1");
        var locked = await SignInWithPasswordAsync(browser, email, PortalApp.Password);

        locked.Url.AbsolutePath.ShouldBe("/Account/Lockout");
        var events = await app.AuditEventsAsync(email);
        events.Select(e => e.Action).ShouldBe(
        [
            .. Enumerable.Repeat(PortalAuditActions.SignInFailed, 5),
            PortalAuditActions.LockedOut,
            PortalAuditActions.SignInFailed,
        ]);
        events[5].Detail.ShouldStartWith("After 5 failed attempts; locked until ");
        events[6].Detail.ShouldStartWith("Account locked");
    }

    [Fact]
    public async Task AWrongAuthenticatorCode_IsAudited()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, authenticator: true);
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email, PortalApp.Password);
        await Browser.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = "000000" });

        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(PortalAuditActions.SignInFailed);
        e.Detail.ShouldStartWith("Wrong authenticator code");
    }

    [Fact]
    public async Task ARecoveryCode_SignsIn_AndTheAuditSaysHowManyAreLeft()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, authenticator: true);
        var codes = await app.RecoveryCodesAsync(email);
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email, PortalApp.Password);
        var home = await Browser.SubmitAsync(browser, $"/Account/LoginWithRecoveryCode{twoFactor.Url.Query}",
            "login-with-recovery-code", new Dictionary<string, string> { ["Input.RecoveryCode"] = codes[0] });

        home.Url.AbsolutePath.ShouldBe("/");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(PortalAuditActions.SignedIn);
        e.Detail.ShouldStartWith("Password and recovery code (9 left)");
    }

    [Fact]
    public async Task AnExpiredPasskeyPrompt_ShowsARetryMessage_AndIsAudited()
    {
        using var browser = app.Browser();
        var before = DateTime.UtcNow.AddSeconds(-1);

        var page = await Browser.SubmitAsync(browser, Login, "login",
            new Dictionary<string, string> { ["Input.Passkey.CredentialJson"] = "{}" });

        page.Status.ShouldBe(HttpStatusCode.OK);
        page.Html.ShouldContain("The passkey prompt expired. Try again.");
        (await app.AuditEventsAsync("(unknown account)")).ShouldContain(e =>
            e.Action == PortalAuditActions.SignInFailed && e.Detail!.StartsWith("Passkey prompt expired") && e.OccurredAt >= before);
    }

    [Fact]
    public async Task Registration_OutsideDevelopment_DoesNotHandOutTheConfirmationLink()
    {
        var email = NewEmail();
        using var browser = app.Browser();

        var page = await Browser.SubmitAsync(browser, "/Account/Register", "register", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = PortalApp.Password,
            ["Input.ConfirmPassword"] = PortalApp.Password,
        });

        page.Url.AbsolutePath.ShouldBe("/Account/RegisterConfirmation");
        page.Html.ShouldNotContain("Account/ConfirmEmail");
        page.Html.ShouldContain("Please check your email to confirm your account.");

        // Unconfirmed, the account can't sign in; the refusal is audited.
        (await SignInWithPasswordAsync(browser, email, PortalApp.Password)).Html.ShouldContain("Invalid login attempt");
        (await app.AuditEventsAsync(email)).ShouldHaveSingleItem().Detail.ShouldStartWith("Sign-in not allowed");
    }

    [Fact]
    public async Task TheAuditTrail_CanNotBeChanged()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email);
        using var browser = app.Browser();
        await SignInWithPasswordAsync(browser, email, "Wrong-password-1");
        var id = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem().Id;

        await Should.ThrowAsync<Exception>(() => app.ExecuteSqlAsync(
            $"""UPDATE portal."AuditEvents" SET "Detail" = 'tampered' WHERE "Id" = {id}"""));
        await Should.ThrowAsync<Exception>(() => app.ExecuteSqlAsync(
            $"""DELETE FROM portal."AuditEvents" WHERE "Id" = {id}"""));
        (await app.AuditEventsAsync(email)).ShouldHaveSingleItem().Detail.ShouldStartWith("Wrong password");
    }

    private static string NewEmail() => $"user-{Guid.NewGuid():N}@example.test";

    private static Task<Page> SignInWithPasswordAsync(HttpClient browser, string email, string password) =>
        Browser.SubmitAsync(browser, Login, "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });
}
