-- A trust domain can require its CA keys to be held in an HSM; key locations gain GCP Cloud HSM.

ALTER TABLE "TrustDomains" ADD COLUMN "RequireHardwareKeys" BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN "TrustDomains"."RequireHardwareKeys" IS 'Whether CA keys in this trust domain must be held in an HSM: new roots and intermediates need an HSM key, and a CA whose key is in software cannot issue or re-sign';

COMMENT ON COLUMN "CaCertificates"."CertSecurityLevel" IS 'Where the key lives: 0 Software (P12 in Sigyll), 1 Fips1403 (HSM), 2 CloudKms (remote key service, software-protected), 3 CloudHsm (GCP Cloud HSM)';

COMMENT ON COLUMN "IssuedCertificates"."CertSecurityLevel" IS 'Where the key lives: 0 Software (P12 in Sigyll), 1 Fips1403 (HSM), 2 CloudKms (remote key service, software-protected), 3 CloudHsm (GCP Cloud HSM)';
