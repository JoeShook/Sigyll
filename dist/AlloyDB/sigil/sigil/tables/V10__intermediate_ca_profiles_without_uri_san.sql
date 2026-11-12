-- The preset Intermediate CA profiles listed URI as a SAN type. Every listed type is required at issuance, so an
-- intermediate CA could not be issued without a URI SAN, which a CA certificate has no use for. Profiles an
-- operator made are left as they are.

UPDATE "CertificateProfiles"
SET "SubjectAltNameTypes" = NULL
WHERE "IsPreset" = TRUE
    AND "CertificateType" = 1
    AND "SubjectAltNameTypes" = 'URI';
