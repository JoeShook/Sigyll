#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Portal.Services;
using Sigyll.Tests;

namespace Sigyll.Portal.Integration.Tests;

/// <summary>Changes people make to their own sign-in security, on the account pages, reach the portal's audit trail.</summary>
[Collection(PortalAppCollection.Name)]
public class SecurityChangeFlowTests(PortalApp app)
{
    [Fact]
    public async Task SettingUpTheAuthenticator_ThenTurningItOff_IsAudited()
    {
        var email = $"user-{Guid.NewGuid():N}@example.test";
        await app.CreateUserAsync(email);
        using var browser = app.Browser();
        await Browser.SubmitAsync(browser, "/Account/Login", "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = PortalApp.Password,
        });

        // The setup page makes a key; the browser's authenticator app reads it and answers with a code.
        await Browser.GetAsync(browser, "/Account/Manage/EnableAuthenticator");
        var key = await app.WithUserAsync(email, (users, user) => users.GetAuthenticatorKeyAsync(user));
        var done = await Browser.SubmitAsync(browser, "/Account/Manage/EnableAuthenticator", "send-code",
            new Dictionary<string, string> { ["Input.Code"] = Totp.Code(key!) });
        done.Html.ShouldContain("recovery codes");
        await Browser.SubmitAsync(browser, "/Account/Manage/Disable2fa", "disable-2fa", new Dictionary<string, string>());

        var changes = (await app.AuditEventsAsync(email)).Where(e => e.Action == PortalAuditActions.SecurityChanged).ToList();
        changes.Select(e => e.Detail).ShouldBe(
        [
            "Authenticator app key reset",
            "Authenticator app turned on",
            "New recovery codes issued (10)",
            "Authenticator app turned off",
            "Recovery codes revoked (10)",
        ]);
        changes.ShouldAllBe(e => e.Actor == email && e.Account == email);
    }
}
