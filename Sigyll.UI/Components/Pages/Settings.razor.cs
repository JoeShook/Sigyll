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
using Sigyll.UI.Components.SettingsSections;

namespace Sigyll.UI.Components.Pages;

/// <summary>
/// Sigyll-wide settings as a grid of cards, one per feature area. Each card is a self-contained component in
/// <c>Components/SettingsSections</c> deriving from <see cref="SettingsCard"/>: closed, it shows a one-line status;
/// opened, it spans the grid and loads and saves its own settings. Add one by listing it in <see cref="Sections"/>;
/// <c>/admin/settings/&lt;id&gt;</c> opens that card.
/// </summary>
public partial class Settings
{
    public sealed record SettingsSection(string Id, Type Component);

    public static readonly IReadOnlyList<SettingsSection> Sections =
    [
        new("vault", typeof(VaultExportSettingsCard)),
    ];

    /// <summary>The card to open, from the URL.</summary>
    [Parameter] public string? Section { get; set; }

    private bool IsOpen(SettingsSection section) => string.Equals(section.Id, Section, StringComparison.OrdinalIgnoreCase);
}
