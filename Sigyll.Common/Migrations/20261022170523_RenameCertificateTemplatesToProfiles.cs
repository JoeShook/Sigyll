using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Sigyll.Common.Migrations
{
    /// <summary>
    /// "Certificate template" became "certificate profile" (the RFC 3647 / NIST / CA-B Forum /
    /// DirectTrust term — see Sigyll/docs/NAMING.md). Pure renames: no data moves. The join
    /// table's key order follows the renamed navigations (Profiles before SanLists).
    /// </summary>
    public partial class RenameCertificateTemplatesToProfiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameTable(
                name: "CertificateTemplates",
                schema: "sigil",
                newName: "CertificateProfiles",
                newSchema: "sigil");

            migrationBuilder.RenameTable(
                name: "CertificateTemplateSanList",
                schema: "sigil",
                newName: "CertificateProfileSanList",
                newSchema: "sigil");

            migrationBuilder.RenameColumn(
                name: "TemplateId",
                schema: "sigil",
                table: "IssuedCertificates",
                newName: "ProfileId");

            migrationBuilder.RenameIndex(
                name: "IX_IssuedCertificates_TemplateId",
                schema: "sigil",
                table: "IssuedCertificates",
                newName: "IX_IssuedCertificates_ProfileId");

            migrationBuilder.RenameIndex(
                name: "IX_CertificateTemplates_Name",
                schema: "sigil",
                table: "CertificateProfiles",
                newName: "IX_CertificateProfiles_Name");

            migrationBuilder.RenameColumn(
                name: "TemplatesId",
                schema: "sigil",
                table: "CertificateProfileSanList",
                newName: "ProfilesId");

            migrationBuilder.Sql("""
                ALTER TABLE sigil."CertificateProfiles" RENAME CONSTRAINT "PK_CertificateTemplates" TO "PK_CertificateProfiles";
                ALTER TABLE sigil."IssuedCertificates" RENAME CONSTRAINT "FK_IssuedCertificates_CertificateTemplates_TemplateId" TO "FK_IssuedCertificates_CertificateProfiles_ProfileId";
                ALTER TABLE sigil."CertificateProfileSanList" RENAME CONSTRAINT "FK_CertificateTemplateSanList_CertificateTemplates_TemplatesId" TO "FK_CertificateProfileSanList_CertificateProfiles_ProfilesId";
                ALTER TABLE sigil."CertificateProfileSanList" RENAME CONSTRAINT "FK_CertificateTemplateSanList_SanLists_SanListsId" TO "FK_CertificateProfileSanList_SanLists_SanListsId";
                ALTER SEQUENCE sigil."CertificateTemplates_Id_seq" RENAME TO "CertificateProfiles_Id_seq";
                """);

            migrationBuilder.DropPrimaryKey(
                name: "PK_CertificateTemplateSanList",
                schema: "sigil",
                table: "CertificateProfileSanList");

            migrationBuilder.DropIndex(
                name: "IX_CertificateTemplateSanList_TemplatesId",
                schema: "sigil",
                table: "CertificateProfileSanList");

            migrationBuilder.AddPrimaryKey(
                name: "PK_CertificateProfileSanList",
                schema: "sigil",
                table: "CertificateProfileSanList",
                columns: new[] { "ProfilesId", "SanListsId" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateProfileSanList_SanListsId",
                schema: "sigil",
                table: "CertificateProfileSanList",
                column: "SanListsId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_CertificateProfileSanList_SanListsId",
                schema: "sigil",
                table: "CertificateProfileSanList");

            migrationBuilder.DropPrimaryKey(
                name: "PK_CertificateProfileSanList",
                schema: "sigil",
                table: "CertificateProfileSanList");

            migrationBuilder.AddPrimaryKey(
                name: "PK_CertificateTemplateSanList",
                schema: "sigil",
                table: "CertificateProfileSanList",
                columns: new[] { "SanListsId", "ProfilesId" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateTemplateSanList_TemplatesId",
                schema: "sigil",
                table: "CertificateProfileSanList",
                column: "ProfilesId");

            migrationBuilder.Sql("""
                ALTER SEQUENCE sigil."CertificateProfiles_Id_seq" RENAME TO "CertificateTemplates_Id_seq";
                ALTER TABLE sigil."CertificateProfileSanList" RENAME CONSTRAINT "FK_CertificateProfileSanList_SanLists_SanListsId" TO "FK_CertificateTemplateSanList_SanLists_SanListsId";
                ALTER TABLE sigil."CertificateProfileSanList" RENAME CONSTRAINT "FK_CertificateProfileSanList_CertificateProfiles_ProfilesId" TO "FK_CertificateTemplateSanList_CertificateTemplates_TemplatesId";
                ALTER TABLE sigil."IssuedCertificates" RENAME CONSTRAINT "FK_IssuedCertificates_CertificateProfiles_ProfileId" TO "FK_IssuedCertificates_CertificateTemplates_TemplateId";
                ALTER TABLE sigil."CertificateProfiles" RENAME CONSTRAINT "PK_CertificateProfiles" TO "PK_CertificateTemplates";
                """);

            migrationBuilder.RenameColumn(
                name: "ProfilesId",
                schema: "sigil",
                table: "CertificateProfileSanList",
                newName: "TemplatesId");

            migrationBuilder.RenameIndex(
                name: "IX_CertificateProfiles_Name",
                schema: "sigil",
                table: "CertificateProfiles",
                newName: "IX_CertificateTemplates_Name");

            migrationBuilder.RenameIndex(
                name: "IX_IssuedCertificates_ProfileId",
                schema: "sigil",
                table: "IssuedCertificates",
                newName: "IX_IssuedCertificates_TemplateId");

            migrationBuilder.RenameColumn(
                name: "ProfileId",
                schema: "sigil",
                table: "IssuedCertificates",
                newName: "TemplateId");

            migrationBuilder.RenameTable(
                name: "CertificateProfileSanList",
                schema: "sigil",
                newName: "CertificateTemplateSanList",
                newSchema: "sigil");

            migrationBuilder.RenameTable(
                name: "CertificateProfiles",
                schema: "sigil",
                newName: "CertificateTemplates",
                newSchema: "sigil");
        }
    }
}
