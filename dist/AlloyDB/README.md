# Database schemas (Flyway)

Sigyll's PostgreSQL schemas are owned by [Flyway](https://documentation.red-gate.com/flyway). EF Core is
used for queries only; the apps never create or migrate tables.

| Database | Schema | Used by | Migrations |
|---|---|---|---|
| `sigil` | `sigil` | CA (`Sigyll`): PKI model, operator sign-in, recurring jobs | [`sigil/sigil/tables`](sigil/sigil/tables) |
| `portal` | `portal` | Certificate request portal (`Sigyll.Portal`) | [`portal/portal/tables`](portal/portal/tables) |

Layout per database: `dist/AlloyDB/<database>/<schema>/` with `flyway.conf` and `tables/V<n>__<description>.sql`.

- `V0__schema_privileges.sql` grants the conventional group roles (`role_<schema>_admin`, `_read_nophi`,
  `_read_phi`, `_write`) when they exist; on a developer database it does nothing.
- `V1__schema.sql` is the baseline (every table, column comments included).
- `V2__flyway_takeover.sql` finishes the move from EF Core migrations (see *Upgrading* below).

## SQL style rules

Every migration follows these rules; `python tools/sql-lint/check_sql.py` checks them and runs in CI.

1. **Keywords and type names in DDL are UPPERCASE**: `CREATE TABLE`, `NOT NULL`, `CHARACTER VARYING(200)`,
   `TIMESTAMP WITH TIME ZONE`, `BOOLEAN`, `COMMENT ON COLUMN`.
2. **Unquoted identifiers are lowercase.** Table and column names are quoted PascalCase to match the
   EF Core model (`"CaCertificates"."NotAfter"`); anything unquoted is lowercase. Index methods count as
   identifiers: `USING btree`, never `USING BTREE`.
3. **Every table and every column has a comment**: a `COMMENT ON TABLE` for each `CREATE TABLE`, and a
   `COMMENT ON COLUMN` for each column created or added with `ALTER TABLE ... ADD COLUMN`. Say what the
   column means, its units, and the meaning of enum values (`0 Pending, 1 Fulfilled, 2 Cancelled`).
4. **Migrations are never edited once merged.** Change the schema with a new `V<n+1>__<what_changed>.sql`.

DML (`INSERT`, `UPDATE`, ...), string literals and `DO $$ ... $$` bodies are not checked.

## Adding a migration

1. Change the entity and its configuration in the `DbContext` as usual.
2. Print the DDL EF would create, and copy the statements you need into a new V file:
   ```
   dotnet ef dbcontext script --project Sigyll.Common --startup-project Sigyll.Common
   ```
   (for the portal: `--project Sigyll.Portal --startup-project Sigyll.Portal`). Drop the `sigil.`/`portal.`
   schema prefix (Flyway sets the default schema), uppercase the types, and add the comments.
3. `python tools/sql-lint/check_sql.py`
4. Under the Aspire AppHost: restart the `sigil-flyway` (or `portal-flyway`) resource, then rebuild the app.
   A rebuild alone does not run new migrations.

## Under the Aspire AppHost

`Sigyll.AppHost` runs PostgreSQL as a persistent container (`sigyll-postgres`, volume `sigyll-postgres-data`,
image `postgres:17.6`), creates the `sigil` and `portal` databases, runs `sigil-flyway` and `portal-flyway`,
and only then starts the apps, handing them their connection strings. Nothing to install or configure.

### Sharing a Postgres you already run

Aspire reuses a persistent container whose name and spec match, instead of creating one. To put Sigyll's
databases in a container other projects' AppHosts already share, override the defaults from
[`Sigyll.AppHost/appsettings.json`](../../Sigyll.AppHost/appsettings.json) in the AppHost's user secrets,
which stay out of source control:

```bash
cd Sigyll.AppHost
dotnet user-secrets set Parameters:postgres-password "<that container's postgres password>"
dotnet user-secrets set Postgres:ContainerName "<its container name>"
dotnet user-secrets set Postgres:DataVolume "<its data volume>"
dotnet user-secrets set Postgres:ImageTag "<its postgres image tag>"
# Only if those AppHosts stamp the container with their Aspire version in an environment variable:
dotnet user-secrets set Postgres:AspireVersionVariable "<that variable's name>"
# The host port the container publishes is part of its spec. Aspire saves the port it picks for a
# persistent container in each AppHost's user secrets (Resources:<resource>:tcp:port); use theirs:
dotnet user-secrets set Resources:postgres:tcp:port "<the port the other AppHosts saved>"
```

The port matters as much as the rest: if this AppHost picks its own port, the AppHosts take turns
recreating the container, each on its own port.

Every value must match what the other AppHosts declare, and Sigyll.AppHost must be on the same Aspire
version: any difference makes Aspire recreate the shared container (the data survives on the volume, but
the other AppHosts lose their connections). With `AspireVersionVariable` set, Sigyll.AppHost refuses to
start against a container that belongs to a newer Aspire version.

To move existing Sigyll data into the shared container: create the `sigil` and `portal` databases there, copy
each schema with `pg_dump -Fc -n <schema> | pg_restore --no-owner --no-privileges`, and start the AppHost;
Flyway adopts the copies.

## Running without the AppHost

Create the databases once (as a PostgreSQL superuser), then run Flyway before starting the app:

```
CREATE ROLE sigil LOGIN PASSWORD 'sigil_pass';
CREATE DATABASE sigil OWNER sigil;
CREATE DATABASE portal OWNER sigil;
```

```
docker run --rm -v "$PWD/dist/AlloyDB/sigil/sigil:/flyway/sql:ro" flyway/flyway:10 \
  -url=jdbc:postgresql://host.docker.internal:5432/sigil -user=sigil -password=sigil_pass \
  -schemas=sigil -defaultSchema=sigil -locations=filesystem:/flyway/sql migrate
```

Use `portal` in place of `sigil` for the portal database.

## Upgrading a database created by EF Core migrations

Databases created before 2026-10-22 were built by EF Core migrations. To move one to Flyway:

1. Run the last EF-migrated build (commit `6ce09bd`) once, so EF applies its final migrations.
2. Run Flyway with `-baselineOnMigrate=true -baselineVersion=1` (the AppHost does this). Flyway records the
   existing schema as V1 and applies `V2__flyway_takeover.sql`, which drops EF's `__EFMigrationsHistory`
   tables. V2 stops with a clear error if step 1 was skipped.
