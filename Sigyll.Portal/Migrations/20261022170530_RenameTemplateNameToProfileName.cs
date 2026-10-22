using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigyll.Portal.Migrations
{
    /// <inheritdoc />
    public partial class RenameTemplateNameToProfileName : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "TemplateName",
                schema: "portal",
                table: "CertificateRequests",
                newName: "ProfileName");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "ProfileName",
                schema: "portal",
                table: "CertificateRequests",
                newName: "TemplateName");
        }
    }
}
