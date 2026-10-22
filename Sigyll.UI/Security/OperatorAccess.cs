#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.FluentUI.AspNetCore.Components;

namespace Sigyll.UI.Security;

/// <summary>
/// What the signed-in operator may do, for one circuit. Pages read the flags to hide or disable
/// controls; every state-changing handler also calls <see cref="EnsureAsync"/> first, because a
/// hidden button is not a permission check (handlers run on the server and can be invoked
/// regardless of what the markup shows).
/// </summary>
public class OperatorAccess
{
    private readonly AuthenticationStateProvider _authState;
    private readonly IAuthorizationService _authorization;
    private readonly IToastService _toast;
    private readonly ILogger<OperatorAccess> _logger;

    public OperatorAccess(
        AuthenticationStateProvider authState,
        IAuthorizationService authorization,
        IToastService toast,
        ILogger<OperatorAccess> logger)
    {
        _authState = authState;
        _authorization = authorization;
        _toast = toast;
        _logger = logger;
    }

    public bool CanOperate { get; private set; }
    public bool CanAdminister { get; private set; }
    public bool CanExportKeys { get; private set; }

    /// <summary>Evaluates the operator's permissions; call from OnInitializedAsync.</summary>
    public async Task LoadAsync()
    {
        CanOperate = await IsAllowedAsync(SigyllPolicies.Operate);
        CanAdminister = await IsAllowedAsync(SigyllPolicies.Administer);
        CanExportKeys = await IsAllowedAsync(SigyllPolicies.ExportKeys);
    }

    /// <summary>
    /// Re-evaluates <paramref name="policy"/> against the current user. Returns false, logs the
    /// attempt and tells the operator when the action is not allowed.
    /// </summary>
    public async Task<bool> EnsureAsync(string policy)
    {
        if (await IsAllowedAsync(policy))
            return true;

        var user = (await _authState.GetAuthenticationStateAsync()).User;
        _logger.LogWarning("Operator {User} was refused an action requiring policy {Policy}",
            user.Identity?.Name ?? "(anonymous)", policy);
        _toast.ShowWarning("Your role does not allow this action.");
        return false;
    }

    private async Task<bool> IsAllowedAsync(string policy)
    {
        var user = (await _authState.GetAuthenticationStateAsync()).User;
        return (await _authorization.AuthorizeAsync(user, policy)).Succeeded;
    }
}
