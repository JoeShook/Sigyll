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

namespace Sigyll.Common.Data;

/// <summary>
/// Encrypts key passwords stored before a master key was configured. Runs at startup once
/// <see cref="KeyPasswordProtection"/> has a key; a no-op when every password is already encrypted.
/// </summary>
public static class KeyPasswordMigration
{
    /// <returns>The number of rows re-encrypted.</returns>
    public static async Task<int> EncryptStoredPasswordsAsync(SigyllDbContext db, CancellationToken ct = default)
    {
        if (!KeyPasswordProtection.IsEnabled)
        {
            return 0;
        }

        // Plain-text rows are found in SQL: through EF the converter would hide which rows are encrypted.
        var pattern = KeyPasswordProtection.Prefix + "%";
        var caIds = await db.Database.SqlQuery<int>(
            $"""SELECT "Id" AS "Value" FROM sigil."CaCertificates" WHERE "PfxPassword" IS NOT NULL AND "PfxPassword" NOT LIKE {pattern}""")
            .ToListAsync(ct);
        var issuedIds = await db.Database.SqlQuery<int>(
            $"""SELECT "Id" AS "Value" FROM sigil."IssuedCertificates" WHERE "PfxPassword" IS NOT NULL AND "PfxPassword" NOT LIKE {pattern}""")
            .ToListAsync(ct);
        var requestIds = await db.Database.SqlQuery<int>(
            $"""SELECT "Id" AS "Value" FROM sigil."ExternalCertificateRequests" WHERE "KeyPassword" NOT LIKE {pattern}""")
            .ToListAsync(ct);

        if (caIds.Count + issuedIds.Count + requestIds.Count == 0)
        {
            return 0;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(ct);

        foreach (var ca in await db.CaCertificates.Where(c => caIds.Contains(c.Id)).ToListAsync(ct))
        {
            db.Entry(ca).Property(c => c.PfxPassword).IsModified = true;
        }

        foreach (var cert in await db.IssuedCertificates.Where(c => issuedIds.Contains(c.Id)).ToListAsync(ct))
        {
            db.Entry(cert).Property(c => c.PfxPassword).IsModified = true;
        }

        foreach (var request in await db.ExternalCertificateRequests.Where(r => requestIds.Contains(r.Id)).ToListAsync(ct))
        {
            db.Entry(request).Property(r => r.KeyPassword).IsModified = true;
        }

        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);

        return caIds.Count + issuedIds.Count + requestIds.Count;
    }
}
