#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Sigyll.Common.Data;
using Sigyll.Common.Security;
using Sigyll.Common.Services.Audit;
using Sigyll.Services;

namespace Sigyll.Auth.Tests;

/// <summary>An Admin's Unlock and Reset second factor on the Operators page.</summary>
public class OperatorAccountServiceTests
{
    private const string Email = "operator@sigyll.test";

    private static readonly OperatorIdentity Admin =
        OperatorIdentity.System("admin@sigyll.test", RolePermissions.For([SigyllRoles.Admin]).ToArray());

    private static readonly OperatorIdentity CaOperator =
        OperatorIdentity.System("ca-operator@sigyll.test", RolePermissions.For([SigyllRoles.CaOperator]).ToArray());

    private readonly DbContextOptions<SigyllDbContext> _auditDb = new DbContextOptionsBuilder<SigyllDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString())
        .Options;

    [Fact]
    public async Task Unlock_EndsTheLockout_AndClearsTheCount()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email);
        using (var request = identity.Request())
        {
            var user = await request.UserAsync(Email);
            await request.Users.AccessFailedAsync(user);
            await request.Users.AccessFailedAsync(user);
            await request.Users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(15));
        }

        using (var request = identity.Request())
            await Service(request, Admin).UnlockAsync(await request.UserAsync(Email));

        using var check = identity.Request();
        var unlocked = await check.UserAsync(Email);
        (await check.Users.IsLockedOutAsync(unlocked)).ShouldBeFalse();
        (await check.Users.GetAccessFailedCountAsync(unlocked)).ShouldBe(0);
        (await check.OperatorSignIn.PasswordAsync(Email, TestIdentity.Password)).Result.Succeeded.ShouldBeTrue();

        var events = await AuditEventsAsync();
        events.Count.ShouldBe(1);
        events[0].Action.ShouldBe(AuditActions.OperatorUnlocked);
        events[0].Actor.ShouldBe(Admin.Name);
        events[0].EntityName.ShouldBe(Email);
    }

    [Fact]
    public async Task ResetSecondFactor_RemovesTheAuthenticatorAndPasskeys_AndEndsSessions()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true, passkeys: 2);
        string stamp, key;
        using (var request = identity.Request())
        {
            var user = await request.UserAsync(Email);
            stamp = (await request.Users.GetSecurityStampAsync(user))!;
            key = (await request.Users.GetAuthenticatorKeyAsync(user))!;
        }

        using (var request = identity.Request())
            await Service(request, Admin).ResetSecondFactorAsync(await request.UserAsync(Email));

        using var check = identity.Request();
        var reset = await check.UserAsync(Email);
        (await check.Users.GetTwoFactorEnabledAsync(reset)).ShouldBeFalse();
        (await check.Users.GetPasskeysAsync(reset)).ShouldBeEmpty();
        (await check.Users.GetAuthenticatorKeyAsync(reset)).ShouldNotBe(key);
        (await check.Users.GetSecurityStampAsync(reset)).ShouldNotBe(stamp);

        var events = await AuditEventsAsync();
        events.Count.ShouldBe(1);
        events[0].Action.ShouldBe(AuditActions.OperatorSecondFactorReset);
        events[0].Detail.ShouldBe("Removed: authenticator app, 2 passkeys; sessions ended.");
    }

    [Fact]
    public async Task ResetSecondFactor_RevokesTheOldRecoveryCodes()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);
        string oldCode;
        using (var request = identity.Request())
            oldCode = (await request.Users.GenerateNewTwoFactorRecoveryCodesAsync(await request.UserAsync(Email), 10))!.First();

        using (var request = identity.Request())
            await Service(request, Admin).ResetSecondFactorAsync(await request.UserAsync(Email));

        // The operator sets up a new authenticator app; setup only issues new codes when none are left.
        using var check = identity.Request();
        var user = await check.UserAsync(Email);
        (await check.Users.CountRecoveryCodesAsync(user)).ShouldBe(0);
        await check.Users.SetTwoFactorEnabledAsync(user, true);
        (await check.Users.RedeemTwoFactorRecoveryCodeAsync(user, oldCode)).Succeeded.ShouldBeFalse();

        (await AuditEventsAsync()).Single().Detail.ShouldBe("Removed: authenticator app, 10 recovery codes; sessions ended.");
    }

    [Fact]
    public async Task OnlyAnAdmin_CanUnlockOrReset()
    {
        await using var identity = new TestIdentity();
        await identity.CreateOperatorAsync(Email, authenticator: true);
        using (var request = identity.Request())
            await request.Users.SetLockoutEndDateAsync(await request.UserAsync(Email), DateTimeOffset.UtcNow.AddMinutes(15));

        using (var request = identity.Request())
        {
            var service = Service(request, CaOperator);
            var user = await request.UserAsync(Email);
            await Should.ThrowAsync<OperatorAccessDeniedException>(() => service.UnlockAsync(user));
            await Should.ThrowAsync<OperatorAccessDeniedException>(() => service.ResetSecondFactorAsync(user));
        }

        using var check = identity.Request();
        var unchanged = await check.UserAsync(Email);
        (await check.Users.IsLockedOutAsync(unchanged)).ShouldBeTrue();
        (await check.Users.GetTwoFactorEnabledAsync(unchanged)).ShouldBeTrue();
        (await AuditEventsAsync()).ShouldBeEmpty();
    }

    private OperatorAccountService Service(TestRequest request, OperatorIdentity actor)
    {
        var context = new OperatorContext();
        context.RunAs(actor);
        return new OperatorAccountService(request.Users, new AuditTrail(new AuditDbFactory(_auditDb), context), context);
    }

    private async Task<List<Sigyll.Common.Data.Entities.AuditEvent>> AuditEventsAsync()
    {
        await using var db = new SigyllDbContext(_auditDb);
        return await db.AuditEvents.ToListAsync();
    }

    private sealed class AuditDbFactory(DbContextOptions<SigyllDbContext> options) : IDbContextFactory<SigyllDbContext>
    {
        public SigyllDbContext CreateDbContext() => new(options);
    }
}
