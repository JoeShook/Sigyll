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
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Sigyll.UI.Security;

namespace Sigyll.Signing.Tests;

public class SigyllPoliciesTests
{
    private readonly IAuthorizationService _authorization;

    public SigyllPoliciesTests()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options => options.AddSigyllPolicies());
        _authorization = services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    // Role → expected (View, Operate, Administer, ExportKeys)
    [Theory]
    [InlineData(SigyllRoles.Auditor, true, false, false, false)]
    [InlineData(SigyllRoles.CaOperator, true, true, false, false)]
    [InlineData(SigyllRoles.Admin, true, true, true, false)]
    [InlineData(SigyllRoles.KeyCustodian, true, false, false, true)]
    public async Task EachRoleGetsOnlyItsPolicies(
        string role, bool view, bool operate, bool administer, bool exportKeys)
    {
        var user = Operator(role);

        (await AllowedAsync(user, SigyllPolicies.View)).ShouldBe(view);
        (await AllowedAsync(user, SigyllPolicies.Operate)).ShouldBe(operate);
        (await AllowedAsync(user, SigyllPolicies.Administer)).ShouldBe(administer);
        (await AllowedAsync(user, SigyllPolicies.ExportKeys)).ShouldBe(exportKeys);
    }

    [Fact]
    public async Task SignedInAccountWithoutRoleIsRefusedEverything()
    {
        var user = Operator();

        (await AllowedAsync(user, SigyllPolicies.View)).ShouldBeFalse();
        (await AllowedAsync(user, SigyllPolicies.Operate)).ShouldBeFalse();
        (await AllowedAsync(user, SigyllPolicies.ExportKeys)).ShouldBeFalse();
    }

    [Fact]
    public async Task AdminNeedsKeyCustodianToExportKeys()
    {
        (await AllowedAsync(Operator(SigyllRoles.Admin), SigyllPolicies.ExportKeys)).ShouldBeFalse();
        (await AllowedAsync(Operator(SigyllRoles.Admin, SigyllRoles.KeyCustodian), SigyllPolicies.ExportKeys)).ShouldBeTrue();
    }

    private static ClaimsPrincipal Operator(params string[] roles)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, "operator@example.org") };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }

    private async Task<bool> AllowedAsync(ClaimsPrincipal user, string policy) =>
        (await _authorization.AuthorizeAsync(user, policy)).Succeeded;
}
