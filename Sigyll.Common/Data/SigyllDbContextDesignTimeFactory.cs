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
using Microsoft.EntityFrameworkCore.Design;

namespace Sigyll.Common.Data;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> run with Sigyll.Common as both project and startup
/// project, so migrations can be scaffolded without building (or stopping) the Blazor host:
///
/// <code>dotnet ef migrations add &lt;Name&gt; --project Sigyll.Common --startup-project Sigyll.Common</code>
///
/// Scaffolding never opens a connection; the connection string only needs to be well-formed.
/// Applying migrations still happens at host startup against the configured SigyllDb.
/// </summary>
public sealed class SigyllDbContextDesignTimeFactory : IDesignTimeDbContextFactory<SigyllDbContext>
{
    public SigyllDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("SIGYLL_DESIGN_TIME_CONNECTION")
            ?? "Host=localhost;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil";

        var options = new DbContextOptionsBuilder<SigyllDbContext>()
            .UseNpgsql(connectionString, npgsql => npgsql.MigrationsHistoryTable("__EFMigrationsHistory", "sigil"))
            .Options;

        return new SigyllDbContext(options);
    }
}
