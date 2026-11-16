CREATE TABLE database_upgrades (
    to_version integer PRIMARY KEY,
    from_version integer NOT NULL CHECK (from_version < to_version),
    migration_sha256 text NOT NULL CHECK (migration_sha256 ~ '^[0-9a-f]{64}$'),
    backup_id text NOT NULL,
    backup_sha256 text NOT NULL CHECK (backup_sha256 ~ '^[0-9a-f]{64}$'),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 27) NOT VALID;
UPDATE memberid_schema SET version = 27;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
