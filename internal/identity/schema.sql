CREATE TABLE memberid_schema (
    version integer PRIMARY KEY CHECK (version = 7)
);
INSERT INTO memberid_schema(version) VALUES (7);

CREATE TABLE organizations (
    id text COLLATE "C" PRIMARY KEY CHECK (id ~ '^org_[0-9bcdfghjkmnpqrstvwxz]{27}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    status text NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE members (
    id text COLLATE "C" PRIMARY KEY CHECK (id ~ '^mbr_[0-9bcdfghjkmnpqrstvwxz]{27}$'),
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    manual_block boolean NOT NULL DEFAULT false,
    external_departure boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, organization_id)
);
CREATE INDEX member_directory ON members (organization_id, created_at, id);

CREATE TABLE authentication_factors (
    id text COLLATE "C" PRIMARY KEY CHECK (id ~ '^af_[0-9bcdfghjkmnpqrstvwxz]{27}$'),
    type text NOT NULL CHECK (type IN ('phone', 'dingtalk')),
    namespace text NOT NULL CHECK (char_length(namespace) BETWEEN 1 AND 512),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (type, namespace, subject),
    UNIQUE (id, type)
);

CREATE TABLE member_auth_factor_bindings (
    id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    member_id text COLLATE "C" NOT NULL,
    organization_id text COLLATE "C" NOT NULL,
    authentication_factor_id text COLLATE "C" NOT NULL,
    factor_type text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (member_id, factor_type),
    FOREIGN KEY (member_id, organization_id) REFERENCES members(id, organization_id),
    FOREIGN KEY (authentication_factor_id, factor_type) REFERENCES authentication_factors(id, type),
    UNIQUE (organization_id, authentication_factor_id),
    CHECK ((status = 'active' AND revoked_at IS NULL) OR (status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE TABLE phone_challenges (
    id text COLLATE "C" PRIMARY KEY,
    phone_number text NOT NULL,
    binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
    code_mac bytea NOT NULL CHECK (octet_length(code_mac) = 32),
    ready boolean NOT NULL DEFAULT false,
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX phone_challenge_rate_limit ON phone_challenges (phone_number, created_at);

CREATE TABLE oidc_sessions (
    id text COLLATE "C" PRIMARY KEY,
    secret_hash text NOT NULL UNIQUE,
    verification jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE TABLE oidc_authorization_requests (
    id text COLLATE "C" PRIMARY KEY,
    client_id text NOT NULL,
    data jsonb NOT NULL,
    code_hash text UNIQUE,
    revision bigint NOT NULL DEFAULT 1,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE TABLE oidc_grants (
    id text COLLATE "C" PRIMARY KEY,
    client_id text NOT NULL,
    session_id text COLLATE "C" NOT NULL REFERENCES oidc_sessions(id) ON DELETE CASCADE,
    data jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE TABLE oidc_access_tokens (
    id text COLLATE "C" PRIMARY KEY,
    grant_id text COLLATE "C" NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    data jsonb NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX oidc_requests_expiry ON oidc_authorization_requests(expires_at);
CREATE INDEX oidc_sessions_expiry ON oidc_sessions(expires_at);
CREATE INDEX oidc_grants_expiry ON oidc_grants(expires_at);
CREATE INDEX oidc_access_expiry ON oidc_access_tokens(expires_at);

CREATE TABLE oidc_refresh_tokens (
    id text COLLATE "C" PRIMARY KEY,
    secret_hash text NOT NULL UNIQUE,
    grant_id text COLLATE "C" NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    data jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX oidc_refresh_family ON oidc_refresh_tokens(grant_id);

CREATE TABLE organization_enrollments (
    organization_id text COLLATE "C" PRIMARY KEY REFERENCES organizations(id),
    member_id text COLLATE "C" NOT NULL,
    binding_id uuid NOT NULL UNIQUE REFERENCES member_auth_factor_bindings(id),
    authentication_factor_id text COLLATE "C" NOT NULL REFERENCES authentication_factors(id),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (member_id, organization_id) REFERENCES members(id, organization_id)
);

CREATE TABLE dingtalk_applications (
    organization_id text COLLATE "C" PRIMARY KEY REFERENCES organizations(id),
    namespace text COLLATE "C" NOT NULL UNIQUE,
    corp_id text NOT NULL,
    client_id text NOT NULL UNIQUE,
    revision bigint NOT NULL CHECK (revision > 0),
    secret_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE dingtalk_identities (
    member_id text COLLATE "C" PRIMARY KEY,
    organization_id text COLLATE "C" NOT NULL REFERENCES dingtalk_applications(organization_id),
    union_id text COLLATE "C" NOT NULL,
    external_member_id text COLLATE "C" NOT NULL,
    department_ids jsonb CHECK (department_ids IS NULL OR jsonb_typeof(department_ids)='array'),
    verified_at timestamptz NOT NULL,
    FOREIGN KEY (member_id,organization_id) REFERENCES members(id,organization_id),
    UNIQUE (organization_id,union_id),
    UNIQUE (organization_id,external_member_id)
);
CREATE UNIQUE INDEX oidc_dingtalk_state ON oidc_authorization_requests ((data->'dingtalk'->>'stateHash')) WHERE data->'dingtalk' IS NOT NULL;
