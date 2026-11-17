CREATE TABLE oidc_clients (
    client_id text COLLATE "C" PRIMARY KEY CHECK (client_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL,
    system boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    registration jsonb NOT NULL,
    CHECK (NOT system OR enabled),
    CHECK ((registration->>'client_id') IS NOT DISTINCT FROM client_id)
);
CREATE INDEX oidc_grants_client_active ON oidc_grants (client_id) WHERE revoked_at IS NULL;
ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 29) NOT VALID;
UPDATE memberid_schema SET version = 29;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
