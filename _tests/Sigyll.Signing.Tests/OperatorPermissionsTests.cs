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
using NSubstitute;
using Shouldly;
using Sigyll.Common.Security;
using Sigyll.Common.Services.Jobs;
using Sigyll.UI.Security;

namespace Sigyll.Signing.Tests;

public class OperatorPermissionsTests
{
    // Role → expected (View, Operate, Administer, ExportKeys)
    [Theory]
    [InlineData(SigyllRoles.Auditor, true, false, false, false)]
    [InlineData(SigyllRoles.CaOperator, true, true, false, false)]
    [InlineData(SigyllRoles.Admin, true, true, true, false)]
    [InlineData(SigyllRoles.KeyCustodian, true, false, false, true)]
    public void EachRoleGetsOnlyItsPermissions(
        string role, bool view, bool operate, bool administer, bool exportKeys)
    {
        var identity = OperatorIdentity.FromPrincipal(Principal(role));

        identity.Has(Permission.View).ShouldBe(view);
        identity.Has(Permission.Operate).ShouldBe(operate);
        identity.Has(Permission.Administer).ShouldBe(administer);
        identity.Has(Permission.ExportKeys).ShouldBe(exportKeys);
        identity.Has(Permission.IssueFromRa).ShouldBeFalse();
    }

    [Fact]
    public void AdminNeedsKeyCustodianToExportKeys()
    {
        OperatorIdentity.FromPrincipal(Principal(SigyllRoles.Admin)).Has(Permission.ExportKeys).ShouldBeFalse();
        OperatorIdentity.FromPrincipal(Principal(SigyllRoles.Admin, SigyllRoles.KeyCustodian))
            .Has(Permission.ExportKeys).ShouldBeTrue();
    }

    [Fact]
    public void SignedInAccountWithoutRoleHoldsNothing()
    {
        OperatorIdentity.FromPrincipal(Principal()).Permissions.ShouldBeEmpty();
    }

    [Fact]
    public void UnauthenticatedPrincipalIsAnonymous()
    {
        OperatorIdentity.FromPrincipal(new ClaimsPrincipal(new ClaimsIdentity())).ShouldBe(OperatorIdentity.Anonymous);
        OperatorIdentity.FromPrincipal(null).ShouldBe(OperatorIdentity.Anonymous);
    }

    [Fact]
    public void SchedulerCanOperateButNotAdministerOrExport()
    {
        var scheduler = RecurringJobRunner.Scheduler;

        scheduler.Has(Permission.Operate).ShouldBeTrue();
        scheduler.Has(Permission.Administer).ShouldBeFalse();
        scheduler.Has(Permission.ExportKeys).ShouldBeFalse();
    }

    [Fact]
    public async Task UnclaimedScopeIsAnonymous()
    {
        var context = new OperatorContext();

        (await context.GetCurrentAsync()).ShouldBe(OperatorIdentity.Anonymous);
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => context.DemandAsync(Permission.View).AsTask());
    }

    [Fact]
    public async Task SignedInUserComesFromThePrincipalSource()
    {
        var source = Substitute.For<IOperatorPrincipalSource>();
        source.GetPrincipalAsync().Returns(new ValueTask<ClaimsPrincipal?>(Principal(SigyllRoles.CaOperator)));
        var context = new OperatorContext(source);

        var identity = await context.DemandAsync(Permission.Operate);

        identity.Name.ShouldBe("operator@example.org");
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => context.DemandAsync(Permission.Administer).AsTask());
    }

    [Fact]
    public async Task RunAsOverridesTheSignedInUserAndCannotBeSwitched()
    {
        var source = Substitute.For<IOperatorPrincipalSource>();
        source.GetPrincipalAsync().Returns(new ValueTask<ClaimsPrincipal?>(Principal(SigyllRoles.Admin)));
        var context = new OperatorContext(source);
        var ra = OperatorIdentity.System("ra-client", Permission.IssueFromRa);

        context.RunAs(ra);

        (await context.GetCurrentAsync()).ShouldBe(ra);
        await Should.ThrowAsync<OperatorAccessDeniedException>(() => context.DemandAsync(Permission.Administer).AsTask());
        Should.Throw<InvalidOperationException>(() => context.RunAs(RecurringJobRunner.Scheduler));
    }

    [Fact]
    public async Task DemandAcceptsAnyOfThePermissions()
    {
        var context = TestOperators.With(Permission.IssueFromRa);

        await context.DemandAsync(Permission.Operate, Permission.IssueFromRa);
        var denied = await Should.ThrowAsync<OperatorAccessDeniedException>(
            () => context.DemandAsync(Permission.Operate).AsTask());
        denied.Required.ShouldBe([Permission.Operate]);
    }

    // The ASP.NET policies are built from the same role map the services use.
    [Theory]
    [InlineData(SigyllRoles.Auditor, true, false)]
    [InlineData(SigyllRoles.CaOperator, true, false)]
    [InlineData(SigyllRoles.Admin, true, false)]
    [InlineData(SigyllRoles.KeyCustodian, true, true)]
    public async Task RoutePoliciesMatchTheRoleMap(string role, bool view, bool exportKeys)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options => options.AddSigyllPolicies());
        var authorization = services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
        var user = Principal(role);

        (await authorization.AuthorizeAsync(user, SigyllPolicies.View)).Succeeded.ShouldBe(view);
        (await authorization.AuthorizeAsync(user, SigyllPolicies.ExportKeys)).Succeeded.ShouldBe(exportKeys);
        (await authorization.AuthorizeAsync(Principal(), SigyllPolicies.View)).Succeeded.ShouldBeFalse();
    }

    private static ClaimsPrincipal Principal(params string[] roles)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, "operator@example.org") };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }
}
