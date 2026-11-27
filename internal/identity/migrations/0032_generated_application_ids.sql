-- The upgrader validates and stages application_id_cutover in this transaction.
ALTER TABLE saml_name_ids DROP CONSTRAINT saml_name_ids_service_provider_id_fkey,
    ADD FOREIGN KEY (service_provider_id) REFERENCES saml_service_providers(id) ON UPDATE CASCADE;
ALTER TABLE authentication_requests DROP CONSTRAINT authentication_requests_saml_service_provider_id_fkey,
    ADD FOREIGN KEY (saml_service_provider_id) REFERENCES saml_service_providers(id) ON UPDATE CASCADE;

UPDATE authentication_requests SET consumed_at = now()
    WHERE consumed_at IS NULL AND (protocol = 'saml' OR client_id <> '');
UPDATE oidc_grants SET revoked_at = now() WHERE revoked_at IS NULL;
UPDATE oidc_clients c SET client_id = m.new_id,
    registration = jsonb_set(c.registration, '{client_id}', to_jsonb(m.new_id))
    FROM application_id_cutover m WHERE m.protocol = 'oidc' AND c.client_id = m.old_id;
UPDATE saml_service_providers sp SET id = m.new_id,
    data = jsonb_set(sp.data, '{id}', to_jsonb(m.new_id))
    FROM application_id_cutover m WHERE m.protocol = 'saml' AND sp.id = m.old_id;

CREATE TABLE application_ids (
    id text COLLATE "C" PRIMARY KEY
);
CREATE FUNCTION reserve_application_id() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO application_ids(id) VALUES (to_jsonb(NEW)->>TG_ARGV[0]);
    RETURN NEW;
END;
$$;
CREATE TRIGGER oidc_reserve_application_id AFTER INSERT ON oidc_clients
    FOR EACH ROW EXECUTE FUNCTION reserve_application_id('client_id');
CREATE TRIGGER saml_reserve_application_id AFTER INSERT ON saml_service_providers
    FOR EACH ROW EXECUTE FUNCTION reserve_application_id('id');
-- Reserve the previous namespace too, including legacy IDs that already look generated.
INSERT INTO application_ids(id) SELECT new_id FROM application_id_cutover
    UNION SELECT old_id FROM application_id_cutover;

ALTER TABLE memberid_schema DROP CONSTRAINT memberid_schema_version_check;
ALTER TABLE memberid_schema ADD CONSTRAINT memberid_schema_version_check CHECK (version = 32) NOT VALID;
UPDATE memberid_schema SET version = 32;
ALTER TABLE memberid_schema VALIDATE CONSTRAINT memberid_schema_version_check;
