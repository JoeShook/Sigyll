using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Sigyll.Common.Migrations
{
    /// <inheritdoc />
    public partial class AddExternalCertificateRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ExternalCertificateRequests",
                schema: "sigil",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    TrustDomainId = table.Column<int>(type: "integer", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    SubjectDn = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    SubjectAltNamesJson = table.Column<string>(type: "text", nullable: true),
                    CsrPem = table.Column<string>(type: "text", nullable: false),
                    KeyAlgorithm = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    PublicKeyThumbprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    EncryptedPrivateKeyPem = table.Column<string>(type: "text", nullable: false),
                    KeyPassword = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ExternalCaName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Notes = table.Column<string>(type: "text", nullable: true),
                    ModeledOnCertificateId = table.Column<int>(type: "integer", nullable: true),
                    ModeledOnEntityType = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FulfilledAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FulfilledCertificateId = table.Column<int>(type: "integer", nullable: true),
                    FulfilledEntityType = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    FulfilledThumbprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalCertificateRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ExternalCertificateRequests_TrustDomains_TrustDomainId",
                        column: x => x.TrustDomainId,
                        principalSchema: "sigil",
                        principalTable: "TrustDomains",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ExternalCertificateRequests_PublicKeyThumbprint",
                schema: "sigil",
                table: "ExternalCertificateRequests",
                column: "PublicKeyThumbprint");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalCertificateRequests_TrustDomainId",
                schema: "sigil",
                table: "ExternalCertificateRequests",
                column: "TrustDomainId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ExternalCertificateRequests",
                schema: "sigil");
        }
    }
}
