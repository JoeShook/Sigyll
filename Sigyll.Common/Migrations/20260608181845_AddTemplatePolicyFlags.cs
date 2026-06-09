using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigyll.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddTemplatePolicyFlags : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllowAutoIssue",
                schema: "sigil",
                table: "CertificateTemplates",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "RequiresRaApproval",
                schema: "sigil",
                table: "CertificateTemplates",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            // Apply the intended RA-portal policy to existing preset templates (the seeder only runs
            // on a fresh database). TLS server certs auto-issue after domain validation; UDAP client
            // certs always require human RA approval.
            migrationBuilder.Sql(
                "UPDATE sigil.\"CertificateTemplates\" SET \"AllowAutoIssue\" = true " +
                "WHERE \"IsPreset\" = true AND \"Name\" = 'SSL Server';");
            migrationBuilder.Sql(
                "UPDATE sigil.\"CertificateTemplates\" SET \"RequiresRaApproval\" = true " +
                "WHERE \"IsPreset\" = true AND \"Name\" = 'UDAP Client';");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowAutoIssue",
                schema: "sigil",
                table: "CertificateTemplates");

            migrationBuilder.DropColumn(
                name: "RequiresRaApproval",
                schema: "sigil",
                table: "CertificateTemplates");
        }
    }
}
