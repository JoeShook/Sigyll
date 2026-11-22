-- A certificate profile can list certificate policy OIDs, which issued certificates carry in the certificatePolicies
-- extension (RFC 5280 section 4.2.1.4). Existing profiles list none, so their certificates are unchanged.

ALTER TABLE "CertificateProfiles" ADD COLUMN "CertificatePolicyOids" CHARACTER VARYING(2000);

COMMENT ON COLUMN "CertificateProfiles"."CertificatePolicyOids" IS 'Semicolon-delimited certificate policy OIDs written into the certificatePolicies extension (2.5.29.32); null leaves the extension out';
