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
using Sigyll.Common.Security;

namespace Sigyll.UI.Security;

/// <summary>
/// ASP.NET Core authorization policies for routes and endpoints, one per <see cref="Permission"/>,
/// built from <see cref="RolePermissions"/> so they cannot drift from what the services enforce.
/// These keep anonymous and role-less users off the pages; the services make the real decision.
/// </summary>
public static class SigyllPolicies
{
    public const string View = "Sigyll.View";
    public const string ExportKeys = "Sigyll.ExportKeys";

    public static void AddSigyllPolicies(this AuthorizationOptions options)
    {
        options.AddPolicy(View, p => p.RequireRole(RolePermissions.RolesGranting(Permission.View)));
        options.AddPolicy(ExportKeys, p => p.RequireRole(RolePermissions.RolesGranting(Permission.ExportKeys)));
    }
}
