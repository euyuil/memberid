CREATE TABLE memberid_schema (
    version integer PRIMARY KEY CHECK (version = 2)
);
INSERT INTO memberid_schema(version) VALUES (2);

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
