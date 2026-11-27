ALTER TABLE organization_login_slugs DROP CONSTRAINT organization_login_slugs_slug_check;
ALTER TABLE organization_login_slugs ADD CONSTRAINT organization_login_slugs_slug_check CHECK (
    char_length(slug) BETWEEN 1 AND 63 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
    AND slug <> 'system'
);

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 36) NOT VALID;
UPDATE memberid_schema SET version = 36;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
