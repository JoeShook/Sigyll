#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Security;

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

/// <summary>What an operation requires. Services check these; roles and system actors grant them.</summary>
public enum Permission
{
    /// <summary>Read certificates, CRLs, configuration and status.</summary>
    View,

    /// <summary>Issue, renew, re-key, revoke, import, generate and publish CRLs, run jobs.</summary>
    Operate,

    /// <summary>Change configuration (trust domains, profiles, schedules) and destroy keys or CAs.</summary>
    Administer,

    /// <summary>Export private keys.</summary>
    ExportKeys,

    /// <summary>Issue a certificate from a CSR an RA has vetted; held only by the RA client.</summary>
    IssueFromRa,
}

/// <summary>The single mapping from operator roles to permissions.</summary>
public static class RolePermissions
{
    private static readonly Dictionary<string, Permission[]> Map = new(StringComparer.Ordinal)
    {
        [SigyllRoles.Auditor] = [Permission.View],
        [SigyllRoles.CaOperator] = [Permission.View, Permission.Operate],
        [SigyllRoles.Admin] = [Permission.View, Permission.Operate, Permission.Administer],
        [SigyllRoles.KeyCustodian] = [Permission.View, Permission.ExportKeys],
    };

    public static IEnumerable<Permission> For(IEnumerable<string> roles) =>
        roles.SelectMany(r => Map.TryGetValue(r, out var p) ? p : []).Distinct();

    public static string[] RolesGranting(Permission permission) =>
        Map.Where(kv => kv.Value.Contains(permission)).Select(kv => kv.Key).ToArray();
}
