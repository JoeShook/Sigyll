-- Flyway takes over the schema from EF Core migrations (2026-10-22). An existing database is
-- baselined at V1; EF's migration history is no longer used. A fresh database gets a no-op.

DROP TABLE IF EXISTS "__EFMigrationsHistory";
