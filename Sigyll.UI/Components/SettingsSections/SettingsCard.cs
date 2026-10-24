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

namespace Sigyll.UI.Components.SettingsSections;

/// <summary>
/// A card on the Settings page. Closed, it shows a short status; opened, it spans the page's grid
/// (<see cref="CardClass"/>) and shows its full settings.
/// </summary>
public abstract class SettingsCard : ComponentBase
{
    /// <summary>Open the card when the page renders (the URL named it).</summary>
    [Parameter] public bool Expanded { get; set; }

    protected bool IsOpen { get; private set; }

    protected string CardClass => IsOpen ? "settings-card-open" : "";

    protected override void OnParametersSet()
    {
        if (Expanded) IsOpen = true;
    }

    protected void Toggle() => IsOpen = !IsOpen;
}
