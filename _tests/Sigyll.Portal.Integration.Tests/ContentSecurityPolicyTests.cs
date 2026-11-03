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

namespace Sigyll.Portal.Integration.Tests;

/// <summary>
/// The portal enforces its content security policy (scripts from the portal itself only), so no page may carry an
/// inline script: the browser would refuse it and the page would break.
/// </summary>
[Collection(PortalAppCollection.Name)]
public class ContentSecurityPolicyTests(PortalApp app)
{
    [Theory]
    [InlineData("/")]
    [InlineData("/Account/Login")]
    [InlineData("/Account/Register")]
    [InlineData("/Account/ForgotPassword")]
    public async Task PublicPages_EnforceThePolicy_AndCarryNoInlineScript(string path)
    {
        using var browser = app.Browser();

        var response = await browser.GetAsync(path);

        response.Headers.Contains("Content-Security-Policy-Report-Only").ShouldBeFalse();
        response.Headers.GetValues("Content-Security-Policy").Single().ShouldContain("script-src 'self';");
        InlineScripts.In(await response.Content.ReadAsStringAsync()).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("/requests")]
    [InlineData("/requests/new")]
    [InlineData("/Account/Manage")]
    [InlineData("/Account/Manage/TwoFactorAuthentication")]
    [InlineData("/Account/Manage/Passkeys")]
    [InlineData("/Account/Manage/EnableAuthenticator")]
    public async Task SignedInPages_CarryNoInlineScript(string path)
    {
        var email = $"csp-{Guid.NewGuid():N}@example.test";
        await app.CreateUserAsync(email);
        using var browser = app.Browser();
        await Browser.SubmitAsync(browser, "/Account/Login", "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = PortalApp.Password,
        });

        var page = await Browser.GetAsync(browser, path);

        page.Url.AbsolutePath.ShouldBe(path);
        InlineScripts.In(page.Html).ShouldBeEmpty();
    }
}
