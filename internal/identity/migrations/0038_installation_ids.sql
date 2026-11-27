-- The management transaction has locked the source tables and staged the new IDs.
ALTER TABLE organizations DROP CONSTRAINT organizations_id_check, DROP CONSTRAINT organizations_check;
ALTER TABLE members DROP CONSTRAINT members_id_check, DROP CONSTRAINT members_check;
ALTER TABLE organization_login_slugs DROP CONSTRAINT organization_login_slugs_slug_check,
    DROP CONSTRAINT organization_login_slugs_organization_id_check;
ALTER TABLE oidc_clients DROP CONSTRAINT oidc_clients_system_owner_check;

-- Retain the input IDs for validating old immutable update receipts after the move.
ALTER TABLE member_updates ADD COLUMN original_organization_id text, ADD COLUMN original_member_id text;
UPDATE member_updates SET original_organization_id=organization_id,original_member_id=member_id WHERE organization_id='org_system';

-- Defer the built-in identity foreign keys for this transaction only. Restore their
-- original definitions after PostgreSQL has validated every updated reference.
CREATE TEMP TABLE installation_foreign_keys ON COMMIT DROP AS
    SELECT conrelid::regclass AS relation, conname FROM pg_constraint
    WHERE contype='f' AND connamespace='public'::regnamespace AND NOT condeferrable
    AND confrelid IN ('organizations'::regclass,'members'::regclass,'dingtalk_applications'::regclass);
DO $$
DECLARE fk record; rel text; org text := current_setting('memberid.system_id'); root_id text := current_setting('memberid.root_id');
BEGIN
    FOR fk IN SELECT * FROM installation_foreign_keys LOOP
        EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I DEFERRABLE INITIALLY DEFERRED',fk.relation,fk.conname);
    END LOOP;
    UPDATE authentication_factors f SET subject='root' FROM member_auth_factor_bindings b
        WHERE b.member_id='mbr_root' AND b.authentication_factor_id=f.id AND f.type='password' AND f.namespace='org_system';
    UPDATE authentication_factors SET namespace=org WHERE type='password' AND namespace='org_system';
    UPDATE organizations SET id=org WHERE id='org_system';
    UPDATE members SET id=root_id WHERE id='mbr_root';
    FOREACH rel IN ARRAY ARRAY['members','member_emails','member_auth_factor_bindings','saml_service_providers',
        'saml_application_enablements','oidc_application_enablements','organization_enrollments','dingtalk_applications',
        'dingtalk_identities','feishu_applications','member_updates','administrators','management_events','authentication_events'] LOOP
        EXECUTE format('UPDATE %I SET organization_id=$1 WHERE organization_id=%L',rel,'org_system') USING org;
    END LOOP;
    FOREACH rel IN ARRAY ARRAY['member_emails','member_auth_factor_bindings','saml_name_ids','organization_enrollments',
        'dingtalk_identities','member_updates','administrators','system_dingtalk_admissions','management_events','console_sessions','authentication_events'] LOOP
        EXECUTE format('UPDATE %I SET member_id=$1 WHERE member_id=%L',rel,'mbr_root') USING root_id;
    END LOOP;
    UPDATE oidc_clients SET owner_organization_id=org WHERE owner_organization_id='org_system';
    UPDATE member_emails SET updated_by=root_id WHERE updated_by='mbr_root';
    UPDATE saml_name_ids SET created_by=root_id WHERE created_by='mbr_root';
    UPDATE management_events SET actor=root_id WHERE actor='mbr_root';
    UPDATE console_logins SET switch_member_id=root_id WHERE switch_member_id='mbr_root';
END;
$$;
SET CONSTRAINTS ALL IMMEDIATE;
DO $$
DECLARE fk record;
BEGIN
    FOR fk IN SELECT * FROM installation_foreign_keys LOOP
        EXECUTE format('ALTER TABLE %s ALTER CONSTRAINT %I NOT DEFERRABLE',fk.relation,fk.conname);
    END LOOP;
END;
$$;

-- Walk typed identity fields. Display names, protocol audiences, external subjects,
-- NameID values and other user-supplied strings may resemble a legacy ID.
CREATE FUNCTION pg_temp.rekey_identity_json(doc jsonb) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE k text; v jsonb; updated jsonb; result jsonb := doc;
BEGIN
    IF jsonb_typeof(doc)='object' THEN
        FOR k,v IN SELECT * FROM jsonb_each(doc) LOOP
            IF v='"org_system"' AND (k IN ('organizationId','ownerOrganizationId','providerOrganizationId') OR (k='namespace' AND doc->>'type'='password')) THEN
                updated := to_jsonb(current_setting('memberid.system_id'));
            ELSIF v='"mbr_root"' AND (k IN ('memberId','hintSubject') OR (k='id' AND (doc ? 'organizationId' AND doc ? 'displayName' OR doc->>'kind'='member'))) THEN
                updated := to_jsonb(current_setting('memberid.root_id'));
            ELSE
                updated := pg_temp.rekey_identity_json(v);
            END IF;
            IF updated IS DISTINCT FROM v THEN result := jsonb_set(result,ARRAY[k],updated); END IF;
        END LOOP;
    ELSIF jsonb_typeof(doc)='array' THEN
        SELECT coalesce(jsonb_agg(pg_temp.rekey_identity_json(item) ORDER BY pos),'[]'::jsonb)
        INTO result FROM jsonb_array_elements(doc) WITH ORDINALITY a(item,pos);
    END IF;
    RETURN result;
END;
$$;

-- Fresh authorization is required when the organization's claim or the root subject changes.
UPDATE oidc_grants SET revoked_at=coalesce(revoked_at,clock_timestamp()) WHERE data->>'organizationId'='org_system' OR data->>'memberId'='mbr_root';
UPDATE authentication_sessions SET revoked_at=coalesce(revoked_at,clock_timestamp())
    WHERE verification#>>'{factor,namespace}'='org_system' AND verification#>>'{factor,type}'='password';
UPDATE authentication_requests SET consumed_at=coalesce(consumed_at,clock_timestamp())
    WHERE pg_temp.rekey_identity_json(data) IS DISTINCT FROM data;
UPDATE account_link_requests SET state='canceled' WHERE state IN ('ready','pending','consumed') AND data->>'organizationId'='org_system';

DO $$
DECLARE col record;
BEGIN
    FOR col IN SELECT * FROM (VALUES ('oidc_clients','registration'),('saml_service_providers','data'),
        ('authentication_sessions','verification'),('authentication_requests','data'),('oidc_grants','data'),
        ('oidc_access_tokens','data'),('oidc_refresh_tokens','data'),('account_link_requests','data'),
        ('member_updates','response'),('management_events','changes'),('management_events','previous'),('authentication_events','data')) AS fields(rel,field)
    LOOP
        EXECUTE format('UPDATE %I SET %I=pg_temp.rekey_identity_json(%I) WHERE (%I::text LIKE %L OR %I::text LIKE %L) AND pg_temp.rekey_identity_json(%I) IS DISTINCT FROM %I',
            col.rel,col.field,col.field,col.field,'%"org_system"%',col.field,'%"mbr_root"%',col.field,col.field);
    END LOOP;
END;
$$;

ALTER TABLE organizations ADD CHECK (id ~ '^org_[0-9bcdfghjkmnpqrstvwxz]{27}$');
ALTER TABLE members ADD CHECK (id ~ '^mbr_[0-9bcdfghjkmnpqrstvwxz]{27}$');
ALTER TABLE organization_login_slugs ADD CHECK (char_length(slug) BETWEEN 1 AND 63 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$');
ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version=38) NOT VALID;
UPDATE memberid_schema SET version=38;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
