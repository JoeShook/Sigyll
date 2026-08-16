using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigyll.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateRenewalLineage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "RenewalOfId",
                schema: "sigil",
                table: "IssuedCertificates",
                type: "integer",
                nullable: true);

            // defaultValue 1 (not 0): existing rows are their lineage's first issuance
            migrationBuilder.AddColumn<int>(
                name: "Version",
                schema: "sigil",
                table: "IssuedCertificates",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<int>(
                name: "RenewalOfId",
                schema: "sigil",
                table: "CaCertificates",
                type: "integer",
                nullable: true);

            // defaultValue 1 (not 0): existing rows are their lineage's first issuance
            migrationBuilder.AddColumn<int>(
                name: "Version",
                schema: "sigil",
                table: "CaCertificates",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.CreateIndex(
                name: "IX_IssuedCertificates_RenewalOfId",
                schema: "sigil",
                table: "IssuedCertificates",
                column: "RenewalOfId");

            migrationBuilder.CreateIndex(
                name: "IX_CaCertificates_RenewalOfId",
                schema: "sigil",
                table: "CaCertificates",
                column: "RenewalOfId");

            migrationBuilder.AddForeignKey(
                name: "FK_CaCertificates_CaCertificates_RenewalOfId",
                schema: "sigil",
                table: "CaCertificates",
                column: "RenewalOfId",
                principalSchema: "sigil",
                principalTable: "CaCertificates",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_IssuedCertificates_IssuedCertificates_RenewalOfId",
                schema: "sigil",
                table: "IssuedCertificates",
                column: "RenewalOfId",
                principalSchema: "sigil",
                principalTable: "IssuedCertificates",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CaCertificates_CaCertificates_RenewalOfId",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropForeignKey(
                name: "FK_IssuedCertificates_IssuedCertificates_RenewalOfId",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropIndex(
                name: "IX_IssuedCertificates_RenewalOfId",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropIndex(
                name: "IX_CaCertificates_RenewalOfId",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropColumn(
                name: "RenewalOfId",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropColumn(
                name: "Version",
                schema: "sigil",
                table: "IssuedCertificates");

            migrationBuilder.DropColumn(
                name: "RenewalOfId",
                schema: "sigil",
                table: "CaCertificates");

            migrationBuilder.DropColumn(
                name: "Version",
                schema: "sigil",
                table: "CaCertificates");
        }
    }
}
