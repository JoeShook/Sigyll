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
/// Lets <c>dotnet ef</c> design-time commands run with Sigyll.Common as both project and startup
/// project, without building (or stopping) the Blazor host. The schema is owned by Flyway
/// (dist/AlloyDB/sigil); use this to print the DDL EF would create for a model change and copy
/// it into a new V file:
///
/// <code>dotnet ef dbcontext script --project Sigyll.Common --startup-project Sigyll.Common</code>
///
/// It never opens a connection; the connection string only needs to be well-formed.
/// </summary>
public sealed class SigyllDbContextDesignTimeFactory : IDesignTimeDbContextFactory<SigyllDbContext>
{
    public SigyllDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("SIGYLL_DESIGN_TIME_CONNECTION")
            ?? "Host=localhost;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil";

        var options = new DbContextOptionsBuilder<SigyllDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new SigyllDbContext(options);
    }
}
