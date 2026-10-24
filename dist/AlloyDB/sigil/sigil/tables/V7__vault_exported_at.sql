-- Remember when each certificate was last written to Vault, so a renewal of one that's in Vault is offered as an
-- update to the same secret.

ALTER TABLE "CaCertificates" ADD COLUMN "VaultExportedAt" TIMESTAMP WITH TIME ZONE;

ALTER TABLE "IssuedCertificates" ADD COLUMN "VaultExportedAt" TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN "CaCertificates"."VaultExportedAt" IS 'When this CA was last written to Vault (export, backup or update), UTC; null if never';

COMMENT ON COLUMN "IssuedCertificates"."VaultExportedAt" IS 'When this certificate was last written to Vault (export, backup or update), UTC; null if never';

-- Certificates that existed at a trust domain's last full backup were written by it.
UPDATE "CaCertificates" c
SET "VaultExportedAt" = t."VaultLastBackupAt"
FROM "TrustDomains" t
WHERE t."Id" = c."TrustDomainId"
  AND t."VaultLastBackupAt" IS NOT NULL
  AND c."CreatedAt" <= t."VaultLastBackupAt"
  AND NOT c."VaultBackupExcluded";

UPDATE "IssuedCertificates" i
SET "VaultExportedAt" = t."VaultLastBackupAt"
FROM "CaCertificates" c
JOIN "TrustDomains" t ON t."Id" = c."TrustDomainId"
WHERE c."Id" = i."IssuingCaCertificateId"
  AND t."VaultLastBackupAt" IS NOT NULL
  AND i."CreatedAt" <= t."VaultLastBackupAt"
  AND NOT i."VaultBackupExcluded";
