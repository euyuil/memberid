ALTER TABLE organization_enrollments ADD COLUMN idempotency_key uuid UNIQUE;

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 37) NOT VALID;
UPDATE memberid_schema SET version = 37;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
