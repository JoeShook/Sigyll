#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Identity;
using Sigyll.Common.Security;
using Sigyll.Common.Services.Audit;
using Sigyll.Components.Account;
using Sigyll.Data;

namespace Sigyll.Services;

/// <summary>
/// Admin actions on an operator's sign-in: ending a lockout, and resetting a second factor the operator has lost.
/// Each demands <see cref="Permission.Administer"/> and is recorded in the audit trail.
/// </summary>
public class OperatorAccountService
{
    private readonly UserManager<SigyllUser> _users;
    private readonly AuditTrail _audit;
    private readonly IOperatorContext _operator;

    public OperatorAccountService(UserManager<SigyllUser> users, AuditTrail audit, IOperatorContext operatorContext)
    {
        _users = users;
        _audit = audit;
        _operator = operatorContext;
    }

    public async Task UnlockAsync(SigyllUser user)
    {
        var actor = await _operator.DemandAsync(Permission.Administer);
        await _users.SetLockoutEndDateAsync(user, null);
        await _users.ResetAccessFailedCountAsync(user);
        await _audit.RecordAsync(actor, AuditActions.OperatorUnlocked, Target(user), "Lockout ended by an Admin.");
    }

    /// <summary>
    /// For an operator who lost their authenticator or passkeys: removes both, with the recovery codes that go with the
    /// authenticator, and ends their sessions, so they set up a new factor at next sign-in. Setting up the authenticator
    /// again issues new codes only when none are left, so old ones would otherwise keep working.
    /// </summary>
    public async Task ResetSecondFactorAsync(SigyllUser user)
    {
        var actor = await _operator.DemandAsync(Permission.Administer);

        var removed = new List<string>();
        if (await _users.GetTwoFactorEnabledAsync(user))
            removed.Add("authenticator app");
        var recoveryCodes = await OperatorMfa.TurnOffAuthenticatorAsync(_users, user);
        if (recoveryCodes > 0)
            removed.Add(recoveryCodes == 1 ? "1 recovery code" : $"{recoveryCodes} recovery codes");
        await _users.ResetAuthenticatorKeyAsync(user);
        var passkeys = await _users.GetPasskeysAsync(user);
        foreach (var passkey in passkeys)
            await _users.RemovePasskeyAsync(user, passkey.CredentialId);
        if (passkeys.Count > 0) removed.Add(passkeys.Count == 1 ? "1 passkey" : $"{passkeys.Count} passkeys");
        // A new security stamp ends the operator's open sessions.
        await _users.UpdateSecurityStampAsync(user);

        await _audit.RecordAsync(actor, AuditActions.OperatorSecondFactorReset, Target(user),
            $"Removed: {(removed.Count > 0 ? string.Join(", ", removed) : "nothing")}; sessions ended.");
    }

    private static AuditTarget Target(SigyllUser user) => AuditTarget.Operator(user.Email ?? user.UserName ?? user.Id);
}
