ALTER TABLE oidc_clients
    ADD COLUMN owner_organization_id text COLLATE "C" NOT NULL DEFAULT 'org_system' REFERENCES organizations(id),
    ADD CONSTRAINT oidc_clients_system_owner_check CHECK (NOT system OR owner_organization_id = 'org_system');
ALTER TABLE oidc_clients ALTER COLUMN owner_organization_id DROP DEFAULT;

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 31) NOT VALID;
UPDATE memberid_schema SET version = 31;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
