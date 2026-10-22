-- Grants for the conventional group roles role_<schema>_admin, role_<schema>_read_nophi,
-- role_<schema>_read_phi and role_<schema>_write. Hosted environments provision those roles
-- outside Flyway; where a role does not exist (a developer database) its grants are skipped.

DO $$
DECLARE
    v_schema TEXT := '${flyway:defaultSchema}';
    v_admin TEXT := 'role_' || v_schema || '_admin';
    v_readers TEXT[] := ARRAY['role_' || v_schema || '_read_nophi', 'role_' || v_schema || '_read_phi'];
    v_write TEXT := 'role_' || v_schema || '_write';
    v_role TEXT;
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = v_admin) THEN
        EXECUTE format('GRANT USAGE, CREATE ON SCHEMA %I TO %I', v_schema, v_admin);
    END IF;

    FOREACH v_role IN ARRAY v_readers LOOP
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = v_role) THEN
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', v_schema, v_role);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO %I', v_schema, v_role);
        END IF;
    END LOOP;

    IF EXISTS (SELECT FROM pg_roles WHERE rolname = v_write) THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', v_schema, v_write);
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES ON TABLES TO %I', v_schema, v_write);
        -- Table privileges do not cover sequences: without this the app role cannot call nextval()
        -- on identity columns created by later migrations.
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO %I', v_schema, v_write);
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT EXECUTE ON ROUTINES TO %I', v_schema, v_write);
    END IF;
END
$$;
