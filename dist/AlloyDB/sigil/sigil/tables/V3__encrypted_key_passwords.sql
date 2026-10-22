-- Key passwords are stored encrypted with a master key held outside the database ("enc:v1:" + base64 of
-- AES-256-GCM nonce, ciphertext and tag). The app encrypts rows written before that at startup.
-- The ciphertext of a 200-character password no longer fits CHARACTER VARYING(200).

ALTER TABLE "ExternalCertificateRequests" ALTER COLUMN "KeyPassword" TYPE TEXT;

COMMENT ON COLUMN "CaCertificates"."PfxPassword" IS 'Password of EncryptedPfxBytes, encrypted with the key-password master key (enc:v1:)';

COMMENT ON COLUMN "IssuedCertificates"."PfxPassword" IS 'Password of EncryptedPfxBytes, encrypted with the key-password master key (enc:v1:)';

COMMENT ON COLUMN "ExternalCertificateRequests"."KeyPassword" IS 'Password of EncryptedPrivateKeyPem, encrypted with the key-password master key (enc:v1:)';
