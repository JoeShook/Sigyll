#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Services.Audit;
using Sigyll.Tests;

namespace Sigyll.Integration.Tests;

/// <summary>An operator's changes to their own sign-in security, made on the account pages, reach the audit trail.</summary>
[Collection(SigyllAppCollection.Name)]
public class SecurityChangeFlowTests(SigyllApp app)
{
    [Fact]
    public async Task NewRecoveryCodes_AndAPasswordChange_AreAudited()
    {
        var email = $"op-{Guid.NewGuid():N}@sigyll.test";
        var key = await app.CreateOperatorAsync(email);
        using var browser = app.Browser();
        var twoFactor = await Browser.SubmitAsync(browser, "/Account/Login", "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = SigyllApp.Password,
        });
        await Browser.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key!) });

        var codes = await Browser.SubmitAsync(browser, "/Account/Manage/GenerateRecoveryCodes", "generate-recovery-codes",
            new Dictionary<string, string>());
        codes.Html.ShouldContain("recovery codes");
        await Browser.SubmitAsync(browser, "/Account/Manage/ChangePassword", "change-password", new Dictionary<string, string>
        {
            ["Input.OldPassword"] = SigyllApp.Password,
            ["Input.NewPassword"] = "Another-horse-battery-2",
            ["Input.ConfirmPassword"] = "Another-horse-battery-2",
        });

        var changes = (await app.AuditEventsAsync(email)).Where(e => e.Action == AuditActions.OperatorSecurityChanged).ToList();
        changes.Select(e => e.Detail).ShouldBe(["New recovery codes issued (10)", "Password changed"]);
        changes.ShouldAllBe(e => e.Actor == email && e.EntityName == email);
    }
}
