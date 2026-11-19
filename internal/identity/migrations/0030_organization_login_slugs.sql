CREATE TABLE organization_login_slugs (
    slug text COLLATE "C" PRIMARY KEY CHECK (
        char_length(slug) BETWEEN 1 AND 63 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
        AND slug NOT IN ('callback', 'dingtalk', 'feishu', 'system')
    ),
    organization_id text COLLATE "C" NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE RESTRICT
        CHECK (organization_id <> 'org_system')
);

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 30) NOT VALID;
UPDATE memberid_schema SET version = 30;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
