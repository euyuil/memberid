ALTER TABLE oidc_clients ADD COLUMN published boolean NOT NULL DEFAULT false;

CREATE TABLE oidc_application_enablements (
    client_id text COLLATE "C" NOT NULL REFERENCES oidc_clients(client_id),
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    activation_id uuid NOT NULL DEFAULT gen_random_uuid(),
    PRIMARY KEY (client_id, organization_id)
);

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 33) NOT VALID;
UPDATE memberid_schema SET version = 33;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
