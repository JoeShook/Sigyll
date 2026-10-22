using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigyll.Common.Migrations
{
    /// <inheritdoc />
    public partial class ReplaceHangfireWithRecurringJobs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RecurringJobs",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Cron = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    NextRunAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastRunAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastResult = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    LastError = table.Column<string>(type: "text", nullable: true),
                    LastDurationMs = table.Column<int>(type: "integer", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RecurringJobs", x => x.Id);
                });

            // Keep the CRL renewal schedule an operator set in Hangfire, then remove Hangfire's tables.
            // NextRunAt stays null; RecurringJobRunner computes it from the cron at startup.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF to_regclass('sigil.hash') IS NOT NULL THEN
                        INSERT INTO sigil."RecurringJobs" ("Id", "Cron", "Enabled", "UpdatedAt")
                        SELECT 'crl-auto-renewal', h.value, TRUE, now()
                        FROM sigil.hash h
                        WHERE h.key = 'recurring-job:crl-auto-renewal' AND h.field = 'Cron'
                        ON CONFLICT ("Id") DO NOTHING;
                    END IF;
                END
                $$;
                DROP TABLE IF EXISTS sigil.jobparameter, sigil.jobqueue, sigil.state, sigil.job,
                    sigil.aggregatedcounter, sigil.counter, sigil.hash, sigil.list, sigil.lock,
                    sigil.schema, sigil.server, sigil.set CASCADE;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RecurringJobs",
                schema: "sigil");
        }
    }
}
