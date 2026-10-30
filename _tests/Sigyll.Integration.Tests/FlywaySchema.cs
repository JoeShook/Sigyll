#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Npgsql;

namespace Sigyll.Tests;

/// <summary>Builds a database's schema from its Flyway scripts in dist/AlloyDB, as the AppHost's flyway resources do.</summary>
public static class FlywaySchema
{
    /// <summary>Runs dist/AlloyDB/<paramref name="schema"/>/<paramref name="schema"/>/tables/V*.sql in version order.</summary>
    public static async Task ApplyAsync(string connectionString, string schema)
    {
        var scripts = Directory.GetFiles(FindTables(schema), "V*__*.sql")
            .OrderBy(path => int.Parse(Path.GetFileName(path)[1..Path.GetFileName(path).IndexOf("__", StringComparison.Ordinal)]));

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"CREATE SCHEMA IF NOT EXISTS {schema}");
        foreach (var script in scripts)
        {
            var sql = (await File.ReadAllTextAsync(script)).Replace("${flyway:defaultSchema}", schema);
            await ExecuteAsync(connection, $"SET search_path TO {schema};\n{sql}");
        }
    }

    /// <summary>Runs SQL against the database directly, as someone with database access could.</summary>
    public static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, sql);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    private static string FindTables(string schema)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "dist", "AlloyDB", schema, schema, "tables");
            if (Directory.Exists(candidate))
                return candidate;
        }
        throw new DirectoryNotFoundException($"dist/AlloyDB/{schema}/{schema}/tables not found above the test output.");
    }
}
