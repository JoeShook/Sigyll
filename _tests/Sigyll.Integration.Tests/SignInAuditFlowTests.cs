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
using Sigyll.Common.Services.Audit;
using Sigyll.Tests;

namespace Sigyll.Integration.Tests;

/// <summary>
/// Sign-in end to end, the way an operator's browser does it: the real pages and forms, cookies and redirects, and
/// the audit trail read back from PostgreSQL. Each test uses its own operator.
/// </summary>
[Collection(SigyllAppCollection.Name)]
public class SignInAuditFlowTests(SigyllApp app)
{
    private const string Login = "/Account/Login";

    [Fact]
    public async Task PasswordAndAuthenticatorCode_SignIn_ThenSignOut_AreBothAudited()
    {
        var email = NewEmail();
        var key = await app.CreateOperatorAsync(email);
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email, SigyllApp.Password);
        twoFactor.PathAndQuery.ShouldStartWith("/Account/LoginWith2fa");
        (await app.AuditEventsAsync(email)).ShouldBeEmpty();   // the password alone is not a sign-in

        var home = await SigyllApp.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key!) });
        home.Url.AbsolutePath.ShouldBe("/");
        (await SigyllApp.GetAsync(browser, "/")).Url.AbsolutePath.ShouldBe("/");   // the session works

        await SigyllApp.PostWithTokenAsync(browser, "/Account/Manage", "/Account/Logout",
            new Dictionary<string, string> { ["ReturnUrl"] = "" });
        (await SigyllApp.GetAsync(browser, "/")).Url.AbsolutePath.ShouldBe(Login);   // and is over

        var events = await app.AuditEventsAsync(email);
        events.Select(e => e.Action).ShouldBe([AuditActions.OperatorSignedIn, AuditActions.OperatorSignedOut]);
        events[0].Detail.ShouldStartWith("Password and authenticator app");
        events[0].Succeeded.ShouldBeTrue();
        events[0].ActorIsSystem.ShouldBeFalse();
        events[0].EntityType.ShouldBe("Operator");
        events[1].Detail.ShouldStartWith("Signed out");
        events.ShouldAllBe(e => e.OccurredAt > DateTime.UtcNow.AddMinutes(-5));   // stamped by the database
    }

    [Fact]
    public async Task AWrongPassword_IsRefused_AndAudited()
    {
        var email = NewEmail();
        await app.CreateOperatorAsync(email);
        using var browser = app.Browser();

        var page = await SignInWithPasswordAsync(browser, email, "Wrong-password-1");

        page.Url.AbsolutePath.ShouldBe(Login);
        page.Html.ShouldContain("Invalid login attempt");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Succeeded.ShouldBeFalse();
        e.Detail.ShouldStartWith("Wrong password");
    }

    [Fact]
    public async Task AWrongAuthenticatorCode_IsRefused_AndAudited()
    {
        var email = NewEmail();
        await app.CreateOperatorAsync(email);
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email, SigyllApp.Password);
        var page = await SigyllApp.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = "000000" });

        page.Url.AbsolutePath.ShouldBe("/Account/LoginWith2fa");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Detail.ShouldStartWith("Wrong authenticator code");
    }

    [Fact]
    public async Task ARecoveryCode_SignsIn_AndTheAuditSaysHowManyAreLeft()
    {
        var email = NewEmail();
        await app.CreateOperatorAsync(email);
        var codes = await app.RecoveryCodesAsync(email);
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email, SigyllApp.Password);
        var returnUrl = twoFactor.Url.Query;
        var page = await SigyllApp.SubmitAsync(browser, $"/Account/LoginWithRecoveryCode{returnUrl}",
            "login-with-recovery-code", new Dictionary<string, string> { ["Input.RecoveryCode"] = codes[0] });

        // Signed in, and sent to where new codes are made, told how many are left.
        page.Url.AbsolutePath.ShouldBe("/Account/Manage/TwoFactorAuthentication");
        page.Html.ShouldContain("9 recovery codes left");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignedIn);
        e.Detail.ShouldStartWith("Password and recovery code (9 left)");
    }

    [Fact]
    public async Task FiveWrongPasswords_LockTheAccount_AndTheLockoutIsAudited()
    {
        var email = NewEmail();
        await app.CreateOperatorAsync(email);
        using var browser = app.Browser();

        for (var attempt = 1; attempt <= 5; attempt++)
            await SignInWithPasswordAsync(browser, email, "Wrong-password-1");
        var locked = await SignInWithPasswordAsync(browser, email, SigyllApp.Password);

        locked.Url.AbsolutePath.ShouldBe("/Account/Lockout");
        var events = await app.AuditEventsAsync(email);
        events.Select(e => e.Action).ShouldBe(
        [
            .. Enumerable.Repeat(AuditActions.OperatorSignInFailed, 5),
            AuditActions.OperatorLockedOut,
            AuditActions.OperatorSignInFailed,
        ]);
        events[5].Detail.ShouldStartWith("After 5 failed attempts; locked until ");
        events[6].Detail.ShouldStartWith("Account locked");
    }

    [Fact]
    public async Task AnUnknownAccount_IsAudited_UnderTheNameTyped()
    {
        var email = NewEmail();   // never created
        using var browser = app.Browser();

        var page = await SignInWithPasswordAsync(browser, email, "Whatever-password-1");

        page.Html.ShouldContain("Invalid login attempt");
        var e = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem();
        e.Action.ShouldBe(AuditActions.OperatorSignInFailed);
        e.Actor.ShouldBe(email);
        e.Detail.ShouldStartWith("Unknown account");
    }

    [Fact]
    public async Task AnExpiredPasskeyPrompt_ShowsARetryMessage_AndIsAudited()
    {
        using var browser = app.Browser();
        var before = DateTime.UtcNow.AddSeconds(-1);

        // What the browser posts when a passkey prompt completes after its server-side state is gone.
        var page = await SigyllApp.SubmitAsync(browser, Login, "login",
            new Dictionary<string, string> { ["Input.Passkey.CredentialJson"] = "{}" });

        page.Status.ShouldBe(HttpStatusCode.OK);
        page.Html.ShouldContain("The passkey prompt expired. Try again.");
        var events = await app.AuditEventsAsync("(unknown account)");
        events.ShouldContain(e => e.Action == AuditActions.OperatorSignInFailed
            && e.Detail!.StartsWith("Passkey prompt expired") && e.OccurredAt >= before);
    }

    [Fact]
    public async Task TheIdleTimer_EndsTheSession_AndIsAudited()
    {
        var email = NewEmail();
        var key = await app.CreateOperatorAsync(email);
        using var browser = app.Browser();
        await SignInAsync(browser, email, key!);

        // What the browser's idle tracker does when the operator has been away too long.
        var page = await SigyllApp.GetAsync(browser, "/Account/SessionExpired");

        page.Url.AbsolutePath.ShouldBe(Login);
        (await SigyllApp.GetAsync(browser, "/")).Url.AbsolutePath.ShouldBe(Login);
        var events = await app.AuditEventsAsync(email);
        events.Select(e => e.Action).ShouldBe([AuditActions.OperatorSignedIn, AuditActions.OperatorSignedOut]);
        events[1].Detail.ShouldStartWith("Signed out after a period of inactivity");
    }

    [Fact]
    public async Task ASessionPastItsTimeLimit_IsEnded_AndAudited()
    {
        var email = NewEmail();
        var key = await app.CreateOperatorAsync(email);
        using var browser = app.Browser();
        await SignInAsync(browser, email, key!);

        await Task.Delay(SigyllApp.MaxSessionLength + TimeSpan.FromSeconds(1));
        var page = await SigyllApp.GetAsync(browser, "/");

        page.Url.AbsolutePath.ShouldBe(Login);
        var events = await app.AuditEventsAsync(email);
        events.Select(e => e.Action).ShouldBe([AuditActions.OperatorSignedIn, AuditActions.OperatorSignedOut]);
        events[1].Detail.ShouldStartWith("Session reached its time limit");
    }

    [Fact]
    public async Task TheAuditTrail_CanNotBeChanged()
    {
        var email = NewEmail();
        await app.CreateOperatorAsync(email);
        using var browser = app.Browser();
        await SignInWithPasswordAsync(browser, email, "Wrong-password-1");
        var id = (await app.AuditEventsAsync(email)).ShouldHaveSingleItem().Id;

        await Should.ThrowAsync<Exception>(() => app.ExecuteSqlAsync(
            $"""UPDATE sigil."AuditEvents" SET "Detail" = 'tampered' WHERE "Id" = {id}"""));
        await Should.ThrowAsync<Exception>(() => app.ExecuteSqlAsync(
            $"""DELETE FROM sigil."AuditEvents" WHERE "Id" = {id}"""));
        (await app.AuditEventsAsync(email)).ShouldHaveSingleItem().Detail.ShouldStartWith("Wrong password");
    }

    private static string NewEmail() => $"op-{Guid.NewGuid():N}@sigyll.test";

    private static Task<Page> SignInWithPasswordAsync(HttpClient browser, string email, string password) =>
        SigyllApp.SubmitAsync(browser, Login, "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });

    private static async Task SignInAsync(HttpClient browser, string email, string key)
    {
        var twoFactor = await SignInWithPasswordAsync(browser, email, SigyllApp.Password);
        var home = await SigyllApp.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key) });
        home.Url.AbsolutePath.ShouldBe("/");
    }
}
