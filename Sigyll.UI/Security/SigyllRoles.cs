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

namespace Sigyll.UI.Security;

/// <summary>
/// Trusted roles for CA operations, aligned with RFC 3647 §5.2 / NISTIR 7924 role separation.
/// Admin configures the system, manages accounts and is the only role that destroys keys or
/// deletes CAs; CaOperator issues/renews/revokes and manages CRLs; Auditor is read-only;
/// KeyCustodian is the only role that can export private keys. Admin does not imply
/// KeyCustodian, so key export is always an explicit grant. Dual-control ceremonies (Phase 13)
/// layer on top of these; they are workflow gates, not additional roles.
/// </summary>
public static class SigyllRoles
{
    public const string Admin = "Admin";
    public const string CaOperator = "CaOperator";
    public const string Auditor = "Auditor";
    public const string KeyCustodian = "KeyCustodian";

    public static readonly string[] All = [Admin, CaOperator, Auditor, KeyCustodian];
}

/// <summary>
/// Named authorization policies. Pages and download endpoints require <see cref="View"/>;
/// every state-changing action checks one of the others before it runs.
/// </summary>
public static class SigyllPolicies
{
    /// <summary>Read the CA: any operator role. A signed-in account with no role sees nothing.</summary>
    public const string View = "Sigyll.View";

    /// <summary>Issue, renew, re-key, revoke, import, generate CRLs and run jobs.</summary>
    public const string Operate = "Sigyll.Operate";

    /// <summary>Change configuration (trust domains, profiles, schedules) and destroy keys or CAs.</summary>
    public const string Administer = "Sigyll.Administer";

    /// <summary>Export private keys.</summary>
    public const string ExportKeys = "Sigyll.ExportKeys";

    public static void AddSigyllPolicies(this AuthorizationOptions options)
    {
        options.AddPolicy(View, p => p.RequireRole(SigyllRoles.All));
        options.AddPolicy(Operate, p => p.RequireRole(SigyllRoles.CaOperator, SigyllRoles.Admin));
        options.AddPolicy(Administer, p => p.RequireRole(SigyllRoles.Admin));
        options.AddPolicy(ExportKeys, p => p.RequireRole(SigyllRoles.KeyCustodian));
    }
}
