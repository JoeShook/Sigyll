-- Flyway takes over the schema from EF Core migrations (2026-10-22).
--
-- An existing database is baselined at V1 (flyway baseline -baselineVersion=1, or
-- baselineOnMigrate) and must already be at the last EF-migrated build, which created
-- "RecurringJobs" and dropped the Hangfire tables. A fresh database ran V1 and gets no-ops here.

DO $$
BEGIN
    IF to_regclass('"RecurringJobs"') IS NULL THEN
        RAISE EXCEPTION 'Schema predates the Flyway baseline: run the last EF-migrated Sigyll build once, then migrate again';
    END IF;
END
$$;

DROP TABLE IF EXISTS "__EFMigrationsHistory";

DROP TABLE IF EXISTS "__EFMigrationsHistory_Auth";

-- Identity sequences kept the names they had before Communities became Trust Domains.
ALTER SEQUENCE IF EXISTS "Communities_Id_seq" RENAME TO "TrustDomains_Id_seq";

ALTER SEQUENCE IF EXISTS "CommunityBaseUrls_Id_seq" RENAME TO "TrustDomainBaseUrls_Id_seq";
