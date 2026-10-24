-- Export certificates to a HashiCorp Vault KV v2 mount as well as to a file. An Admin sets the Vault server and
-- mount; each trust domain exports under its own folder of that mount.

CREATE TABLE "VaultExportSettings" (
    "Id" INTEGER NOT NULL,
    "Enabled" BOOLEAN NOT NULL,
    "Address" CHARACTER VARYING(500),
    "Mount" CHARACTER VARYING(200) NOT NULL,
    "UpdatedAt" TIMESTAMP WITH TIME ZONE NOT NULL,
    "UpdatedBy" CHARACTER VARYING(256),
    CONSTRAINT "PK_VaultExportSettings" PRIMARY KEY ("Id"),
    CONSTRAINT "CK_VaultExportSettings_Singleton" CHECK ("Id" = 1)
);

COMMENT ON TABLE "VaultExportSettings" IS 'The one row saying whether, and to which Vault KV v2 mount, certificates can be exported';

COMMENT ON COLUMN "VaultExportSettings"."Id" IS 'Always 1 (primary key)';

COMMENT ON COLUMN "VaultExportSettings"."Enabled" IS 'Whether the export buttons offer Vault next to the file download';

COMMENT ON COLUMN "VaultExportSettings"."Address" IS 'Vault server address, e.g. https://vault.example.org:8200';

COMMENT ON COLUMN "VaultExportSettings"."Mount" IS 'KV v2 secrets engine mount, usually secret';

COMMENT ON COLUMN "VaultExportSettings"."UpdatedAt" IS 'When the settings last changed (UTC)';

COMMENT ON COLUMN "VaultExportSettings"."UpdatedBy" IS 'Operator who last changed the settings';

ALTER TABLE "TrustDomains" ADD COLUMN "VaultNamespace" CHARACTER VARYING(200);

COMMENT ON COLUMN "TrustDomains"."VaultNamespace" IS 'Folder under the Vault KV mount this trust domain exports to; set by the first export, changed only by an Admin';
