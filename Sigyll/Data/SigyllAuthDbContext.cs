#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Sigyll.Data;

/// <summary>
/// Identity store for CA operator accounts. Shares the <c>sigil</c> schema with
/// <c>SigyllDbContext</c> (the dev DB user has no CREATE-schema privilege) but is a separate
/// context with its own migrations history table (<c>__EFMigrationsHistory_Auth</c>), keeping
/// authentication concerns out of the PKI data model.
/// </summary>
public class SigyllAuthDbContext(DbContextOptions<SigyllAuthDbContext> options)
    : IdentityDbContext<SigyllUser>(options)
{
    public const string Schema = "sigil";
    public const string MigrationsHistoryTable = "__EFMigrationsHistory_Auth";

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.HasDefaultSchema(Schema);
        base.OnModelCreating(builder);
    }
}
