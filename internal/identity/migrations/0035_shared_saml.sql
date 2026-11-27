CREATE TABLE saml_application_enablements (
    service_provider_id text COLLATE "C" NOT NULL REFERENCES saml_service_providers(id),
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    activation_id uuid NOT NULL DEFAULT gen_random_uuid(),
    PRIMARY KEY (service_provider_id, organization_id)
);

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 35) NOT VALID;
UPDATE memberid_schema SET version = 35;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
