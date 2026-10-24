-- Back up a whole trust domain to its Vault namespace: an Admin turns it on per trust domain.

ALTER TABLE "TrustDomains" ADD COLUMN "VaultBackupEnabled" BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE "TrustDomains" ADD COLUMN "VaultLastBackupAt" TIMESTAMP WITH TIME ZONE;

ALTER TABLE "TrustDomains" ADD COLUMN "VaultLastBackupBy" CHARACTER VARYING(256);

COMMENT ON COLUMN "TrustDomains"."VaultBackupEnabled" IS 'Whether operators can back up every certificate, CRL and (optionally) key file of this trust domain to Vault at once';

COMMENT ON COLUMN "TrustDomains"."VaultLastBackupAt" IS 'When the last full backup to Vault wrote at least one secret (UTC)';

COMMENT ON COLUMN "TrustDomains"."VaultLastBackupBy" IS 'Operator who ran the last full backup to Vault';
