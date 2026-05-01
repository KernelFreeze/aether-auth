CREATE TABLE session_user_agents (
    fingerprint_id TEXT PRIMARY KEY CHECK (fingerprint_id <> ''),
    ip INET,
    description TEXT NOT NULL DEFAULT '',
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER session_user_agents_set_updated_at
BEFORE UPDATE ON session_user_agents
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    client_id UUID,
    kind TEXT NOT NULL CHECK (kind IN ('full', 'partial')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    token_id TEXT,
    user_agent_id TEXT REFERENCES session_user_agents (fingerprint_id) ON DELETE SET NULL,
    ip INET,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX sessions_token_id_key ON sessions (token_id) WHERE token_id IS NOT NULL;
CREATE INDEX sessions_account_active_idx ON sessions (account_id, expires_at) WHERE status = 'active';
CREATE INDEX sessions_client_idx ON sessions (client_id) WHERE client_id IS NOT NULL;

CREATE TRIGGER sessions_set_updated_at
BEFORE UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE session_factors (
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    factor_kind TEXT NOT NULL CHECK (factor_kind IN ('user', 'password', 'passkey', 'idp', 'totp', 'recovery_code')),
    challenge_binding TEXT NOT NULL DEFAULT '',
    verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (session_id, factor_kind)
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    parent_id UUID REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    client_id UUID,
    token_hash BYTEA NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX refresh_tokens_hash_key ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_active_idx ON refresh_tokens (session_id, expires_at) WHERE revoked_at IS NULL AND rotated_at IS NULL;

CREATE TABLE archived_sessions (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    client_id UUID,
    token_id TEXT,
    user_agent_id TEXT REFERENCES session_user_agents (fingerprint_id) ON DELETE SET NULL,
    ip INET,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION archive_deleted_session()
RETURNS trigger AS $$
BEGIN
    INSERT INTO archived_sessions (
        id,
        account_id,
        client_id,
        token_id,
        user_agent_id,
        ip,
        expires_at,
        revoked_at,
        deleted_at,
        created_at,
        updated_at
    )
    VALUES (
        OLD.id,
        OLD.account_id,
        OLD.client_id,
        OLD.token_id,
        OLD.user_agent_id,
        OLD.ip,
        OLD.expires_at,
        OLD.revoked_at,
        now(),
        OLD.created_at,
        OLD.updated_at
    );
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sessions_archive_on_delete
AFTER DELETE ON sessions
FOR EACH ROW
EXECUTE FUNCTION archive_deleted_session();
