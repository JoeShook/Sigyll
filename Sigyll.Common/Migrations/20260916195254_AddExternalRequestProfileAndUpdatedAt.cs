using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigyll.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalRequestProfileAndUpdatedAt : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Profile",
                schema: "sigil",
                table: "ExternalCertificateRequests",
                type: "integer",
                nullable: false,
                // Requests created before this column existed were built with the UI default, UdapClient (1)
                defaultValue: 1);

            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatedAt",
                schema: "sigil",
                table: "ExternalCertificateRequests",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Profile",
                schema: "sigil",
                table: "ExternalCertificateRequests");

            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                schema: "sigil",
                table: "ExternalCertificateRequests");
        }
    }
}
