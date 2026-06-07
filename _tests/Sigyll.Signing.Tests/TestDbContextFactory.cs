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
using Sigyll.Common.Data;

namespace Sigyll.Signing.Tests;

public sealed class TestDbContextFactory : IDbContextFactory<SigyllDbContext>
{
    private readonly DbContextOptions<SigyllDbContext> _options;

    public TestDbContextFactory(DbContextOptions<SigyllDbContext>? options = null)
    {
        _options = options ?? new DbContextOptionsBuilder<SigyllDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        using var db = new SigyllDbContext(_options);
        db.Database.EnsureCreated();
    }

    public SigyllDbContext CreateDbContext() => new(_options);
}
