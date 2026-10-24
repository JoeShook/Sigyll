-- Let operators leave a certificate (and its renewals) out of the full trust domain backup to Vault.

ALTER TABLE "CaCertificates" ADD COLUMN "VaultBackupExcluded" BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE "IssuedCertificates" ADD COLUMN "VaultBackupExcluded" BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN "CaCertificates"."VaultBackupExcluded" IS 'Whether the full backup to Vault leaves this CA out; set on every generation of a renewal lineage';

COMMENT ON COLUMN "IssuedCertificates"."VaultBackupExcluded" IS 'Whether the full backup to Vault leaves this certificate out; set on every generation of a renewal lineage';
