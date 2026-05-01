CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations (id) ON DELETE SET NULL,
    owner_account_id UUID REFERENCES accounts (id) ON DELETE SET NULL,
    client_secret_hash BYTEA,
    name TEXT NOT NULL CHECK (name <> ''),
    redirect_uris TEXT[] NOT NULL CHECK (cardinality(redirect_uris) > 0),
    grant_types TEXT[] NOT NULL DEFAULT '{}',
    response_types TEXT[] NOT NULL DEFAULT '{}',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    confidential BOOLEAN NOT NULL DEFAULT true,
    pkce_required BOOLEAN NOT NULL DEFAULT true,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX oauth_clients_organization_idx ON oauth_clients (organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX oauth_clients_owner_idx ON oauth_clients (owner_account_id) WHERE owner_account_id IS NOT NULL;

CREATE TRIGGER oauth_clients_set_updated_at
BEFORE UPDATE ON oauth_clients
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

ALTER TABLE sessions
    ADD CONSTRAINT sessions_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE SET NULL;

ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE SET NULL;

CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY,
    code_hash BYTEA NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations (id) ON DELETE SET NULL,
    redirect_uri TEXT NOT NULL CHECK (redirect_uri <> ''),
    scopes TEXT[] NOT NULL DEFAULT '{}',
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX authorization_codes_hash_key ON authorization_codes (code_hash);
CREATE INDEX authorization_codes_client_account_idx ON authorization_codes (client_id, account_id);
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes (expires_at);

CREATE TABLE consent_grants (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations (id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX consent_grants_client_account_key
    ON consent_grants (client_id, account_id)
    WHERE organization_id IS NULL;
CREATE UNIQUE INDEX consent_grants_client_account_org_key
    ON consent_grants (client_id, account_id, organization_id)
    WHERE organization_id IS NOT NULL;

CREATE TRIGGER consent_grants_set_updated_at
BEFORE UPDATE ON consent_grants
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE oauth_refresh_tokens (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL,
    session_id UUID REFERENCES sessions (id) ON DELETE CASCADE,
    parent_id UUID REFERENCES oauth_refresh_tokens (id) ON DELETE SET NULL,
    client_id UUID NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX oauth_refresh_tokens_hash_key ON oauth_refresh_tokens (token_hash);
CREATE INDEX oauth_refresh_tokens_session_idx ON oauth_refresh_tokens (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX oauth_refresh_tokens_active_idx
    ON oauth_refresh_tokens (client_id, account_id, expires_at)
    WHERE revoked_at IS NULL AND rotated_at IS NULL;
