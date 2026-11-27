CREATE TABLE installation_identities (
    slug text COLLATE "C" PRIMARY KEY CHECK (slug = 'system') REFERENCES organization_login_slugs(slug),
    root_member_id text COLLATE "C" NOT NULL CHECK (root_member_id ~ '^mbr_[0-9bcdfghjkmnpqrstvwxz]{27}$')
);

CREATE FUNCTION protected_identity_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Permanent installation identity binding' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER keep_installation_identities BEFORE UPDATE OR DELETE ON installation_identities
    FOR EACH ROW EXECUTE FUNCTION protected_identity_change();
CREATE TRIGGER keep_system_login_name BEFORE UPDATE OR DELETE ON organization_login_slugs
    FOR EACH ROW WHEN (OLD.slug='system') EXECUTE FUNCTION protected_identity_change();

CREATE FUNCTION system_organization_id() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT organization_id FROM organization_login_slugs WHERE slug='system';
$$;
CREATE FUNCTION check_system_organization_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id=system_organization_id() AND NEW.status<>'enabled' THEN
        RAISE EXCEPTION 'System organization must remain enabled' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER keep_system_organization_enabled BEFORE UPDATE OF status ON organizations
    FOR EACH ROW EXECUTE FUNCTION check_system_organization_status();

CREATE FUNCTION check_system_application_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system AND NEW.owner_organization_id IS DISTINCT FROM system_organization_id() THEN
        RAISE EXCEPTION 'Protected client must belong to the system organization' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER keep_system_application_owner BEFORE INSERT OR UPDATE ON oidc_clients
    FOR EACH ROW WHEN (NEW.system) EXECUTE FUNCTION check_system_application_owner();

CREATE FUNCTION keep_root_factor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.namespace=system_organization_id() THEN
        RAISE EXCEPTION 'System root password identity is permanent' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER keep_root_factor BEFORE DELETE OR UPDATE OF id,type,namespace,subject ON authentication_factors
    FOR EACH ROW WHEN (OLD.type='password' AND OLD.subject='root') EXECUTE FUNCTION keep_root_factor();

-- Bootstrap inserts the factor and binding in the same transaction.
CREATE FUNCTION check_root_factor_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace=system_organization_id() AND NOT EXISTS (
        SELECT 1 FROM member_auth_factor_bindings b JOIN installation_identities i ON i.root_member_id=b.member_id
        WHERE b.organization_id=NEW.namespace AND b.authentication_factor_id=NEW.id AND b.factor_type='password'
    ) THEN
        RAISE EXCEPTION 'System root username is reserved' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER check_root_factor_owner AFTER INSERT OR UPDATE ON authentication_factors
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.type='password' AND NEW.subject='root')
    EXECUTE FUNCTION check_root_factor_owner();

CREATE FUNCTION keep_root_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.member_id=(SELECT root_member_id FROM installation_identities) THEN
        RAISE EXCEPTION 'System root password binding is permanent' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER keep_root_password_binding BEFORE UPDATE OR DELETE ON member_auth_factor_bindings
    FOR EACH ROW WHEN (OLD.factor_type='password') EXECUTE FUNCTION keep_root_binding();
