#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Tests;

namespace Sigyll.Integration.Tests;

/// <summary>
/// Sigyll enforces its content security policy (scripts from Sigyll itself only), so no page may carry an inline
/// script: the browser would refuse it and the page would break.
/// </summary>
[Collection(SigyllAppCollection.Name)]
public class ContentSecurityPolicyTests(SigyllApp app)
{
    [Fact]
    public async Task TheSignInPage_EnforcesThePolicy_AndCarriesNoInlineScript()
    {
        using var browser = app.Browser();

        var response = await browser.GetAsync("/Account/Login");

        response.Headers.Contains("Content-Security-Policy-Report-Only").ShouldBeFalse();
        response.Headers.GetValues("Content-Security-Policy").Single().ShouldContain("script-src 'self';");
        InlineScripts.In(await response.Content.ReadAsStringAsync()).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/explorer")]
    [InlineData("/certificate-profiles")]
    [InlineData("/credentials")]
    [InlineData("/audit")]
    [InlineData("/Account/Manage/TwoFactorAuthentication")]
    public async Task SignedInPages_CarryNoInlineScript(string path)
    {
        var email = $"csp-{Guid.NewGuid():N}@sigyll.test";
        var key = await app.CreateOperatorAsync(email);
        using var browser = app.Browser();
        var twoFactor = await Browser.SubmitAsync(browser, "/Account/Login", "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = SigyllApp.Password,
        });
        await Browser.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key!) });

        var page = await Browser.GetAsync(browser, path);

        page.Url.AbsolutePath.ShouldBe(path);
        InlineScripts.In(page.Html).ShouldBeEmpty();
    }
}
