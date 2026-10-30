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
using Sigyll.Portal.Data;
using Sigyll.Portal.Data.Entities;

namespace Sigyll.Portal.Services;

/// <summary>The actions the portal's audit trail records. Stored as text: never rename one, add a new code instead.</summary>
public static class PortalAuditActions
{
    public const string SignedIn = "user.signed-in";
    public const string SignInFailed = "user.sign-in-failed";
    public const string LockedOut = "user.locked-out";
    public const string SignedOut = "user.signed-out";
}

/// <summary>
/// The portal's append-only audit trail. Each event is saved in its own database context, so a record never carries
/// along unsaved changes from the request's context.
/// </summary>
public sealed class PortalAuditTrail(DbContextOptions<PortalDbContext> options)
{
    /// <summary>Adds an event. Throws if it can't be stored.</summary>
    public async Task RecordAsync(string actor, string action, string? account, string? detail, bool succeeded = true)
    {
        await using var db = new PortalDbContext(options);
        db.AuditEvents.Add(new AuditEvent
        {
            Actor = Truncate(actor)!,
            Action = action,
            Succeeded = succeeded,
            Account = Truncate(account),
            Detail = detail,
        });
        await db.SaveChangesAsync();
    }

    private static string? Truncate(string? value) => value is { Length: > 256 } ? value[..256] : value;
}
