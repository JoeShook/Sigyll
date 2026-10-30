#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Sigyll.Portal.Components.Account;
using Sigyll.Portal.Services;
using Sigyll.Tests;

namespace Sigyll.Portal.Integration.Tests;

/// <summary>
/// RA staff (RA, PortalAdmin) need a second factor; requesters don't (StaffMfa). End to end through the portal's
/// pages, plus the bootstrap admin that a production portal starts with.
/// </summary>
[Collection(PortalAppCollection.Name)]
public class StaffMfaTests(PortalApp app)
{
    private const string Login = "/Account/Login";
    private const string RaQueue = "/ra/queue";
    private const string Enroll = "/Account/Manage/TwoFactorAuthentication";

    [Fact]
    public async Task TheBootstrapAdmin_ComesFromConfiguration_AndMustAddASecondFactorFirst()
    {
        var roles = await app.WithUserAsync(PortalApp.BootstrapAdmin, async (users, user) => await users.GetRolesAsync(user));
        roles.ShouldBe(["PortalAdmin", "RA"], ignoreOrder: true);
        using var browser = app.Browser();

        var landing = await SignInWithPasswordAsync(browser, PortalApp.BootstrapAdmin);

        landing.PathAndQuery.ShouldBe($"{Enroll}?required=1");
        landing.Html.ShouldContain("RA staff need a second factor.");
        (await Browser.GetAsync(browser, RaQueue)).PathAndQuery.ShouldBe($"{Enroll}?required=1");
        (await Browser.GetAsync(browser, "/requests")).PathAndQuery.ShouldBe($"{Enroll}?required=1");
        (await Browser.GetAsync(browser, "/Account/Manage/Passkeys")).Url.AbsolutePath.ShouldBe("/Account/Manage/Passkeys");
    }

    [Theory]
    [InlineData("RA")]
    [InlineData("PortalAdmin")]
    public async Task StaffWithoutASecondFactor_CanOnlySetOneUp(string role)
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, roles: role);
        using var browser = app.Browser();
        await SignInWithPasswordAsync(browser, email);

        (await Browser.GetAsync(browser, RaQueue)).PathAndQuery.ShouldBe($"{Enroll}?required=1");
        (await Browser.GetAsync(browser, "/")).PathAndQuery.ShouldBe($"{Enroll}?required=1");
    }

    [Fact]
    public async Task StaffWithoutASecondFactor_StillGetThePagesStylesAndScripts()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, roles: "RA");
        using var browser = app.Browser();
        var setup = await SignInWithPasswordAsync(browser, email);
        setup.Url.AbsolutePath.ShouldBe(Enroll);

        var assets = Regex.Matches(setup.Html, """(?:href|src)="([^"]+\.(?:css|js))" """.TrimEnd())
            .Select(m => m.Groups[1].Value)
            .Distinct()
            .ToList();
        assets.ShouldContain(a => a.StartsWith("app.") && a.EndsWith(".css"));   // hashed names, not just app.css

        // Each comes back as it does for a signed-out browser, not as a redirect to the setup page.
        using var anonymous = app.Browser();
        foreach (var asset in assets.Select(a => a.TrimStart('.', '/')))
        {
            var expected = await anonymous.GetAsync(asset);
            var response = await browser.GetAsync(asset);
            response.RequestMessage!.RequestUri!.AbsolutePath.ShouldBe("/" + asset, asset);
            response.StatusCode.ShouldBe(expected.StatusCode, asset);
            // (Package assets under _content aren't served by an unpublished test host, for anyone.)
            if (expected.IsSuccessStatusCode)
                (await response.Content.ReadAsStringAsync()).ShouldBe(await expected.Content.ReadAsStringAsync(), asset);
        }
        (await anonymous.GetAsync(assets.First(a => a.StartsWith("app.")))).IsSuccessStatusCode.ShouldBeTrue();
    }

    [Fact]
    public async Task StaffWithAnAuthenticator_ReachTheRaQueue()
    {
        var email = NewEmail();
        var key = await app.CreateUserAsync(email, authenticator: true, roles: "RA");
        using var browser = app.Browser();

        var twoFactor = await SignInWithPasswordAsync(browser, email);
        await Browser.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key!) });

        (await Browser.GetAsync(browser, RaQueue)).Url.AbsolutePath.ShouldBe(RaQueue);
    }

    [Fact]
    public async Task ARequesterWithoutASecondFactor_IsNotSentToSetOneUp()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email);
        using var browser = app.Browser();
        await SignInWithPasswordAsync(browser, email);

        (await Browser.GetAsync(browser, "/requests")).Url.AbsolutePath.ShouldBe("/requests");
    }

    [Fact]
    public async Task AStaffMembersPassword_DoesNotSignIn_WhenTheirSecondFactorIsAPasskey()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, passkeys: 1, roles: "RA");
        using var browser = app.Browser();

        var page = await SignInWithPasswordAsync(browser, email);

        page.Url.AbsolutePath.ShouldBe(Login);
        page.Html.ShouldContain("This account also needs your passkey");
        (await Browser.GetAsync(browser, "/requests")).Url.AbsolutePath.ShouldBe(Login);
        (await app.AuditEventsAsync(email)).ShouldNotContain(e => e.Action == PortalAuditActions.SignedIn);
    }

    [Fact]
    public async Task AStaffMembersWrongPassword_StillCountsTowardsLockout_WhenTheirSecondFactorIsAPasskey()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, passkeys: 1, roles: "RA");
        using var browser = app.Browser();

        await SignInWithPasswordAsync(browser, email, "Wrong-password-1");

        (await app.WithUserAsync(email, (users, user) => users.GetAccessFailedCountAsync(user))).ShouldBe(1);
        (await app.AuditEventsAsync(email)).ShouldHaveSingleItem().Detail.ShouldStartWith("Wrong password");
    }

    [Fact]
    public async Task StaffCanNotTurnOffTheirOnlySecondFactor()
    {
        var email = NewEmail();
        var key = await app.CreateUserAsync(email, authenticator: true, roles: "RA");
        using var browser = app.Browser();
        await SignInAsync(browser, email, key!);

        var page = await Browser.SubmitAsync(browser, "/Account/Manage/Disable2fa", "disable-2fa", new Dictionary<string, string>());

        page.Url.AbsolutePath.ShouldBe(Enroll);
        page.Html.ShouldContain("RA staff need a second factor. Add a passkey before turning off the authenticator app.");
        (await app.WithUserAsync(email, (users, user) => users.GetTwoFactorEnabledAsync(user))).ShouldBeTrue();
    }

    [Fact]
    public async Task ARequester_CanTurnOffTheAuthenticator_WhichRevokesTheirRecoveryCodes()
    {
        var email = NewEmail();
        var key = await app.CreateUserAsync(email, authenticator: true);
        await app.RecoveryCodesAsync(email);
        using var browser = app.Browser();
        await SignInAsync(browser, email, key!);

        await Browser.SubmitAsync(browser, "/Account/Manage/Disable2fa", "disable-2fa", new Dictionary<string, string>());

        (await app.WithUserAsync(email, (users, user) => users.GetTwoFactorEnabledAsync(user))).ShouldBeFalse();
        (await app.WithUserAsync(email, (users, user) => users.CountRecoveryCodesAsync(user))).ShouldBe(0);
    }

    [Theory]
    [InlineData(false, 1, false)]   // staff: the last passkey stays
    [InlineData(false, 2, true)]
    [InlineData(true, 1, true)]
    public async Task StaffCanRemoveAPasskey_OnlyIfAnotherFactorRemains(bool authenticator, int passkeys, bool allowed)
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, authenticator, passkeys, "RA");

        (await app.WithUserAsync(email, (users, user) => StaffMfa.CanRemovePasskeyAsync(users, user))).ShouldBe(allowed);
    }

    [Fact]
    public async Task ARequester_CanRemoveTheirLastPasskey()
    {
        var email = NewEmail();
        await app.CreateUserAsync(email, passkeys: 1);

        (await app.WithUserAsync(email, (users, user) => StaffMfa.CanRemovePasskeyAsync(users, user))).ShouldBeTrue();
    }

    [Theory]
    [InlineData("Production", null, true)]
    [InlineData("Production", "false", true)]
    [InlineData("Staging", "false", true)]
    [InlineData("Development", null, true)]
    [InlineData("Development", "false", false)]
    public void OnlyDevelopment_CanTurnTheRequirementOff(string environment, string? setting, bool required)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Auth:RequireStaffMfa"] = setting })
            .Build();

        StaffMfa.IsRequired(configuration, new HostEnvironment(environment)).ShouldBe(required);
    }

    private static string NewEmail() => $"staff-{Guid.NewGuid():N}@example.test";

    private static Task<Page> SignInWithPasswordAsync(HttpClient browser, string email, string password = PortalApp.Password) =>
        Browser.SubmitAsync(browser, Login, "login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
        });

    private static async Task SignInAsync(HttpClient browser, string email, string key)
    {
        var twoFactor = await SignInWithPasswordAsync(browser, email);
        (await Browser.SubmitAsync(browser, twoFactor.PathAndQuery, "login-with-2fa",
            new Dictionary<string, string> { ["Input.TwoFactorCode"] = Totp.Code(key) })).Url.AbsolutePath.ShouldBe("/");
    }

    private sealed class HostEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "Sigyll.Portal";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
