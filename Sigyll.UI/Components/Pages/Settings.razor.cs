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
using Microsoft.FluentUI.AspNetCore.Components;
using Sigyll.UI.Components.SettingsSections;
using Icons = Microsoft.FluentUI.AspNetCore.Components.Icons;

namespace Sigyll.UI.Components.Pages;

/// <summary>
/// Sigyll-wide settings, one section per feature area. Each section is a self-contained component (usually one card)
/// in <c>Components/SettingsSections</c> that loads and saves its own settings; add one by listing it in
/// <see cref="Sections"/>. Sections are addressed as <c>/admin/settings/&lt;id&gt;</c>.
/// </summary>
public partial class Settings
{
    public sealed record SettingsSection(string Id, string Title, Icon Icon, string Summary, Type Component);

    public static readonly IReadOnlyList<SettingsSection> Sections =
    [
        new("vault", "Export to Vault", new Icons.Regular.Size20.CloudArrowUp(),
            "Send certificate files to HashiCorp Vault KV, and back up whole trust domains",
            typeof(VaultExportSettingsCard)),
    ];

    /// <summary>The section id from the URL; the first section when there's none.</summary>
    [Parameter] public string? Section { get; set; }

    private SettingsSection? Current => string.IsNullOrEmpty(Section)
        ? Sections[0]
        : Sections.FirstOrDefault(s => string.Equals(s.Id, Section, StringComparison.OrdinalIgnoreCase));
}
