ALTER TABLE oidc_clients ADD CONSTRAINT oidc_clients_organization_scope_check CHECK (
        NOT registration ? 'allowOrganizationScope'
        OR registration @> '{"allowOrganizationScope": false}'
        OR registration @> '{"allowOrganizationScope": true, "subjectKind": "member"}'
    );

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 34) NOT VALID;
UPDATE memberid_schema SET version = 34;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
