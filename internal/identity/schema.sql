CREATE TABLE memberid_schema (
    version integer PRIMARY KEY CHECK (version = 23)
);
INSERT INTO memberid_schema(version) VALUES (23);

CREATE TABLE organizations (
    id text COLLATE "C" PRIMARY KEY CHECK (id = 'org_system' OR id ~ '^org_[0-9bcdfghjkmnpqrstvwxz]{27}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    status text NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'disabled')),
    lifecycle_revision bigint NOT NULL DEFAULT 0 CHECK (lifecycle_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (id <> 'org_system' OR status = 'enabled')
);
INSERT INTO organizations(id,name) VALUES ('org_system','System organization');

CREATE TABLE members (
    id text COLLATE "C" PRIMARY KEY CHECK (id = 'mbr_root' OR id ~ '^mbr_[0-9bcdfghjkmnpqrstvwxz]{27}$'),
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    manual_block boolean NOT NULL DEFAULT false,
    external_departure boolean NOT NULL DEFAULT false,
    eligibility_revision bigint NOT NULL DEFAULT 0 CHECK (eligibility_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, organization_id),
    CHECK (id <> 'mbr_root' OR organization_id = 'org_system')
);
CREATE INDEX member_directory ON members (organization_id, created_at, id);

CREATE TABLE authentication_factors (
    id text COLLATE "C" PRIMARY KEY CHECK (id ~ '^af_[0-9bcdfghjkmnpqrstvwxz]{27}$'),
    type text NOT NULL CHECK (type IN ('phone', 'dingtalk', 'feishu', 'password')),
    namespace text NOT NULL CHECK (char_length(namespace) BETWEEN 1 AND 512),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (type, namespace, subject),
    UNIQUE (id, type),
    UNIQUE (id, type, namespace)
);

CREATE TABLE member_auth_factor_bindings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    member_id text COLLATE "C" NOT NULL,
    organization_id text COLLATE "C" NOT NULL,
    authentication_factor_id text COLLATE "C" NOT NULL,
    factor_type text NOT NULL,
    provider_namespace text,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    FOREIGN KEY (member_id, organization_id) REFERENCES members(id, organization_id),
    FOREIGN KEY (authentication_factor_id, factor_type) REFERENCES authentication_factors(id, type),
    FOREIGN KEY (authentication_factor_id, factor_type, provider_namespace) REFERENCES authentication_factors(id, type, namespace) ON UPDATE CASCADE,
    UNIQUE (organization_id, authentication_factor_id),
    CHECK ((factor_type = 'feishu') = (provider_namespace IS NOT NULL)),
    CHECK ((status = 'active' AND revoked_at IS NULL) OR (status = 'revoked' AND revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX member_single_factor_type ON member_auth_factor_bindings (member_id, factor_type) WHERE factor_type <> 'feishu';
CREATE UNIQUE INDEX member_feishu_source ON member_auth_factor_bindings (member_id, provider_namespace) WHERE factor_type = 'feishu';

CREATE TABLE password_credentials (
    authentication_factor_id text COLLATE "C" PRIMARY KEY REFERENCES authentication_factors(id),
    salt bytea NOT NULL CHECK (octet_length(salt) = 16),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    iterations integer NOT NULL CHECK (iterations BETWEEN 600000 AND 2000000)
);

CREATE TABLE password_attempt_windows (
    account_hash bytea PRIMARY KEY CHECK (octet_length(account_hash) = 32),
    attempts smallint NOT NULL CHECK (attempts BETWEEN 1 AND 10),
    expires_at timestamptz NOT NULL
);
CREATE INDEX password_attempt_expiry ON password_attempt_windows(expires_at);

CREATE TABLE phone_challenges (
    id text COLLATE "C" PRIMARY KEY,
    phone_number text NOT NULL,
    binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash) = 32),
    source_hash bytea NOT NULL CHECK (octet_length(source_hash) = 32),
    client_hash bytea NOT NULL CHECK (octet_length(client_hash) = 32),
    code_mac bytea NOT NULL CHECK (octet_length(code_mac) = 32),
    ready boolean NOT NULL DEFAULT false,
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX phone_challenge_send_window ON phone_challenges (created_at);
CREATE INDEX phone_challenge_rate_limit ON phone_challenges (phone_number, created_at);

CREATE TABLE saml_service_providers (
    id text COLLATE "C" PRIMARY KEY,
    entity_id text COLLATE "C" NOT NULL UNIQUE,
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    revision bigint NOT NULL CHECK (revision > 0),
    data jsonb NOT NULL,
    retired_at timestamptz
);
CREATE TABLE saml_name_ids (
    service_provider_id text COLLATE "C" NOT NULL REFERENCES saml_service_providers(id),
    member_id text COLLATE "C" NOT NULL REFERENCES members(id),
    value text COLLATE "C" NOT NULL,
    PRIMARY KEY (service_provider_id, member_id),
    UNIQUE (service_provider_id, value)
);
CREATE TABLE authentication_sessions (
    id text COLLATE "C" PRIMARY KEY,
    secret_hash text NOT NULL UNIQUE,
    verification jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE TABLE authentication_requests (
    id text COLLATE "C" PRIMARY KEY,
    protocol text NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc','saml')),
    saml_service_provider_id text COLLATE "C" REFERENCES saml_service_providers(id),
    saml_request_id text COLLATE "C",
    client_id text NOT NULL,
    data jsonb NOT NULL,
    code_hash text UNIQUE,
    revision bigint NOT NULL DEFAULT 1,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    UNIQUE (saml_service_provider_id, saml_request_id),
    CHECK ((protocol='saml') = (saml_service_provider_id IS NOT NULL AND saml_request_id IS NOT NULL)),
    CHECK (protocol='oidc' OR code_hash IS NULL)
);
CREATE TABLE oidc_grants (
    id text COLLATE "C" PRIMARY KEY,
    client_id text NOT NULL,
    session_id text COLLATE "C" NOT NULL REFERENCES authentication_sessions(id) ON DELETE CASCADE,
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
CREATE INDEX oidc_requests_expiry ON authentication_requests(expires_at);
CREATE INDEX authentication_sessions_expiry ON authentication_sessions(expires_at);
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
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    namespace text COLLATE "C" PRIMARY KEY,
    display_name text NOT NULL DEFAULT 'DingTalk' CHECK (char_length(display_name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT true,
    corp_id text NOT NULL,
    client_id text NOT NULL UNIQUE,
    revision bigint NOT NULL CHECK (revision > 0),
    secret_ciphertext bytea NOT NULL,
    authorization_status text NOT NULL DEFAULT 'active' CHECK (authorization_status IN ('active', 'revoked')),
    authorization_revision bigint NOT NULL DEFAULT 1 CHECK (authorization_revision > 0),
    directory_revision bigint NOT NULL DEFAULT 0 CHECK (directory_revision >= 0),
    authorization_verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (organization_id,namespace)
);
CREATE INDEX dingtalk_applications_organization ON dingtalk_applications (organization_id, namespace);

CREATE TABLE dingtalk_identities (
    member_id text COLLATE "C" PRIMARY KEY,
    organization_id text COLLATE "C" NOT NULL,
    namespace text COLLATE "C" NOT NULL,
    union_id text COLLATE "C" NOT NULL,
    external_member_id text COLLATE "C" NOT NULL,
    department_ids jsonb CHECK (department_ids IS NULL OR jsonb_typeof(department_ids)='array'),
    verified_at timestamptz NOT NULL,
    last_event_time bigint NOT NULL DEFAULT 0 CHECK (last_event_time >= 0),
    last_event_departure boolean NOT NULL DEFAULT false,
    FOREIGN KEY (member_id,organization_id) REFERENCES members(id,organization_id),
    FOREIGN KEY (organization_id,namespace) REFERENCES dingtalk_applications(organization_id,namespace),
    UNIQUE (namespace,union_id),
    UNIQUE (namespace,external_member_id)
);
CREATE UNIQUE INDEX oidc_dingtalk_state ON authentication_requests ((data->'dingtalk'->>'stateHash')) WHERE data->'dingtalk' IS NOT NULL;

CREATE TABLE dingtalk_events (
    namespace text COLLATE "C" NOT NULL REFERENCES dingtalk_applications(namespace),
    event_id text COLLATE "C" NOT NULL,
    event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace,event_id)
);

CREATE TABLE feishu_applications (
    organization_id text COLLATE "C" NOT NULL REFERENCES organizations(id),
    namespace text COLLATE "C" PRIMARY KEY,
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    enabled boolean NOT NULL,
    tenant_key text NOT NULL,
    client_id text NOT NULL UNIQUE,
    revision bigint NOT NULL CHECK (revision > 0),
    secret_ciphertext bytea NOT NULL,
    authorization_status text NOT NULL DEFAULT 'active' CHECK (authorization_status IN ('active', 'revoked')),
    authorization_revision bigint NOT NULL DEFAULT 1 CHECK (authorization_revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX feishu_applications_organization ON feishu_applications (organization_id, namespace);
CREATE UNIQUE INDEX oidc_feishu_state ON authentication_requests ((data->'feishu'->>'stateHash')) WHERE data->'feishu' IS NOT NULL;

CREATE TABLE account_link_requests (
    id text COLLATE "C" PRIMARY KEY,
    session_id text COLLATE "C" NOT NULL REFERENCES authentication_sessions(id) ON DELETE CASCADE,
    data jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('ready','pending','consumed','completed','canceled')),
    state_hash text UNIQUE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX account_link_session ON account_link_requests(session_id,expires_at);
CREATE INDEX account_link_expiry ON account_link_requests(expires_at);

CREATE TABLE member_updates (
    id uuid PRIMARY KEY,
    organization_id text COLLATE "C" NOT NULL,
    member_id text COLLATE "C" NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    response jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (member_id, organization_id) REFERENCES members(id, organization_id)
);

CREATE TABLE administrators (
    organization_id text COLLATE "C" NOT NULL,
    member_id text COLLATE "C" PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (member_id, organization_id) REFERENCES members(id, organization_id)
);

-- Operator-approved targets, not authentication evidence or administrator grants.
CREATE TABLE system_dingtalk_admissions (
    member_id text COLLATE "C" PRIMARY KEY REFERENCES members(id),
    namespace text COLLATE "C" NOT NULL,
    union_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    UNIQUE(namespace, union_id)
);

CREATE TABLE management_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor text NOT NULL,
    -- Auditing must not acquire organization locks after a Member mutation.
    organization_id text COLLATE "C" NOT NULL,
    member_id text COLLATE "C",
    action text NOT NULL,
    changes jsonb NOT NULL,
    snapshot jsonb NOT NULL DEFAULT '{}',
    previous jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX management_event_directory ON management_events(organization_id,id);

CREATE TABLE console_logins (
    state_hash text PRIMARY KEY,
    browser_hash text NOT NULL,
    verifier text NOT NULL,
    nonce text NOT NULL,
    return_to text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE TABLE console_sessions (
    secret_hash text PRIMARY KEY,
    grant_id text COLLATE "C" NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    member_id text COLLATE "C" NOT NULL REFERENCES members(id),
    csrf text NOT NULL,
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL
);

-- Immutable evidence survives deletion of business records. References deliberately
-- have no foreign keys: delivery can be delayed, reordered, or partially lost.
CREATE TABLE authentication_events (
    event_id text COLLATE "C" PRIMARY KEY,
    event_type text NOT NULL,
    outcome text NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    organization_id text COLLATE "C" NOT NULL DEFAULT '',
    member_id text COLLATE "C" NOT NULL DEFAULT '',
    client_id text COLLATE "C" NOT NULL DEFAULT '',
    interaction_id text COLLATE "C" NOT NULL DEFAULT '',
    request_id text COLLATE "C" NOT NULL DEFAULT '',
    data jsonb NOT NULL CHECK (octet_length(data::text)<=8192)
);
CREATE INDEX authentication_event_time ON authentication_events(occurred_at,event_id);
CREATE INDEX authentication_event_organization ON authentication_events(organization_id,occurred_at,event_id);
CREATE INDEX authentication_event_interaction ON authentication_events(interaction_id,occurred_at,event_id);
