CREATE TABLE auth_challenges (
    id TEXT PRIMARY KEY CHECK (id <> ''),
    purpose TEXT NOT NULL CHECK (purpose IN ('webauthn', 'oidc_state', 'oidc_nonce', 'oidc_pkce')),
    account_id UUID REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id UUID REFERENCES credentials (id) ON DELETE CASCADE,
    provider TEXT,
    session_binding TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    payload BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX auth_challenges_expiry_idx ON auth_challenges (expires_at);
CREATE INDEX auth_challenges_consume_idx
    ON auth_challenges (purpose, session_binding, provider)
    WHERE consumed_at IS NULL;

CREATE TABLE oidc_pending_states (
    id TEXT PRIMARY KEY CHECK (id <> ''),
    provider TEXT NOT NULL CHECK (provider <> ''),
    session_binding TEXT NOT NULL CHECK (session_binding <> ''),
    state_hash BYTEA NOT NULL,
    nonce_hash BYTEA,
    pkce_verifier_ciphertext BYTEA,
    redirect_uri TEXT NOT NULL CHECK (redirect_uri <> ''),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX oidc_pending_states_hash_key ON oidc_pending_states (provider, state_hash);
CREATE INDEX oidc_pending_states_expiry_idx ON oidc_pending_states (expires_at);

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    requested_by_ip INET,
    user_agent TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX password_reset_tokens_hash_key ON password_reset_tokens (token_hash);
CREATE INDEX password_reset_tokens_account_active_idx
    ON password_reset_tokens (account_id, expires_at)
    WHERE used_at IS NULL;
