CREATE TABLE feishu_memberships (
    binding_id uuid PRIMARY KEY REFERENCES member_auth_factor_bindings(id),
    departed boolean NOT NULL DEFAULT false,
    checked_at timestamptz,
    attempted_at timestamptz NOT NULL DEFAULT '-infinity',
    CHECK (NOT departed OR checked_at IS NOT NULL)
);
CREATE INDEX feishu_memberships_due ON feishu_memberships (attempted_at, binding_id);
INSERT INTO feishu_memberships(binding_id) SELECT id FROM member_auth_factor_bindings WHERE factor_type='feishu';
ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 28) NOT VALID;
UPDATE memberid_schema SET version = 28;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
