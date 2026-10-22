#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.Logging;
using Microsoft.FluentUI.AspNetCore.Components;
using Sigyll.Common.Security;

namespace Sigyll.UI.Security;

/// <summary>
/// Wraps the page body. When a service refuses an operation the operator's role does not allow,
/// the refusal is logged, the operator sees a toast and the page is restored, instead of the
/// circuit failing. A page that is refused again straight after being restored (it asks for
/// something on load) shows <see cref="ErrorBoundary.ErrorContent"/> rather than looping.
/// Any other exception is logged and shows <see cref="ErrorBoundary.ErrorContent"/>.
/// </summary>
public class OperatorErrorBoundary : ErrorBoundary
{
    private static readonly TimeSpan RepeatWindow = TimeSpan.FromSeconds(2);
    private DateTime _lastRecoveredAt = DateTime.MinValue;

    [Inject] private IToastService Toast { get; set; } = null!;
    [Inject] private ILogger<OperatorErrorBoundary> Logger { get; set; } = null!;

    protected override async Task OnErrorAsync(Exception exception)
    {
        if (exception is not OperatorAccessDeniedException denied)
        {
            Logger.LogError(exception, "Unhandled error in a page");
            return;
        }

        Logger.LogWarning("Refused {Actor}: the action requires {Required}",
            denied.Actor, string.Join(" or ", denied.Required));
        Toast.ShowWarning("Your role does not allow this action.");

        if (DateTime.UtcNow - _lastRecoveredAt < RepeatWindow)
            return;

        // Let the error state render first, then restore the page.
        await Task.Yield();
        _lastRecoveredAt = DateTime.UtcNow;
        Recover();
    }
}
