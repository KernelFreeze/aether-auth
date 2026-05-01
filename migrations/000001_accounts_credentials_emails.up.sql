CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL CHECK (username <> ''),
    username_normalized TEXT NOT NULL CHECK (username_normalized = lower(username_normalized)),
    display_name TEXT NOT NULL DEFAULT '',
    disabled BOOLEAN NOT NULL DEFAULT false,
    mfa_required BOOLEAN NOT NULL DEFAULT false,
    locked_until TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX accounts_username_normalized_key ON accounts (username_normalized);
CREATE INDEX accounts_locked_until_idx ON accounts (locked_until) WHERE locked_until IS NOT NULL;

CREATE TRIGGER accounts_set_updated_at
BEFORE UPDATE ON accounts
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE emails (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    address TEXT NOT NULL CHECK (address <> ''),
    address_normalized TEXT NOT NULL CHECK (address_normalized = lower(address_normalized)),
    verified BOOLEAN NOT NULL DEFAULT false,
    is_primary BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX emails_address_normalized_key ON emails (address_normalized);
CREATE UNIQUE INDEX emails_one_primary_per_account_idx ON emails (account_id) WHERE is_primary;
CREATE INDEX emails_account_id_idx ON emails (account_id);

CREATE TRIGGER emails_set_updated_at
BEFORE UPDATE ON emails
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE credentials (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('password', 'webauthn', 'oidc', 'totp', 'recovery_code')),
    provider TEXT,
    external_subject TEXT,
    display_name TEXT NOT NULL DEFAULT '',
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK ((kind = 'oidc') = (provider IS NOT NULL AND external_subject IS NOT NULL))
);

CREATE INDEX credentials_account_kind_idx ON credentials (account_id, kind);
CREATE UNIQUE INDEX credentials_provider_subject_key
    ON credentials (kind, provider, external_subject)
    WHERE provider IS NOT NULL AND external_subject IS NOT NULL;
CREATE INDEX credentials_active_account_idx ON credentials (account_id) WHERE revoked_at IS NULL;

CREATE TRIGGER credentials_set_updated_at
BEFORE UPDATE ON credentials
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE credential_payloads (
    credential_id UUID PRIMARY KEY REFERENCES credentials (id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL CHECK (algorithm <> ''),
    key_ref TEXT NOT NULL CHECK (key_ref <> ''),
    nonce BYTEA,
    ciphertext BYTEA NOT NULL,
    aad JSONB NOT NULL DEFAULT '{}'::jsonb,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER credential_payloads_set_updated_at
BEFORE UPDATE ON credential_payloads
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE webauthn_credentials (
    credential_id UUID PRIMARY KEY REFERENCES credentials (id) ON DELETE CASCADE,
    key_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    relying_party_id TEXT NOT NULL CHECK (relying_party_id <> ''),
    aaguid BYTEA,
    attestation_type TEXT NOT NULL DEFAULT '',
    user_verified BOOLEAN NOT NULL DEFAULT false,
    backed_up BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX webauthn_credentials_key_id_key ON webauthn_credentials (key_id);

CREATE TRIGGER webauthn_credentials_set_updated_at
BEFORE UPDATE ON webauthn_credentials
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX recovery_codes_hash_key ON recovery_codes (account_id, code_hash);
CREATE INDEX recovery_codes_unused_idx ON recovery_codes (account_id) WHERE used_at IS NULL;

CREATE TABLE oidc_provider_links (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id UUID REFERENCES credentials (id) ON DELETE SET NULL,
    provider TEXT NOT NULL CHECK (provider <> ''),
    external_subject TEXT NOT NULL CHECK (external_subject <> ''),
    email TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    display_name TEXT NOT NULL DEFAULT '',
    claims JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX oidc_provider_links_provider_subject_key ON oidc_provider_links (provider, external_subject);
CREATE INDEX oidc_provider_links_account_idx ON oidc_provider_links (account_id);

CREATE TRIGGER oidc_provider_links_set_updated_at
BEFORE UPDATE ON oidc_provider_links
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE login_attempts (
    id UUID PRIMARY KEY,
    endpoint TEXT NOT NULL CHECK (endpoint <> ''),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('ip', 'account', 'username')),
    subject_hash TEXT NOT NULL CHECK (subject_hash <> ''),
    account_id UUID REFERENCES accounts (id) ON DELETE CASCADE,
    username_normalized TEXT,
    ip INET,
    failed_count INTEGER NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    locked_until TIMESTAMPTZ,
    last_failed_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX login_attempts_subject_key ON login_attempts (endpoint, subject_type, subject_hash);
CREATE INDEX login_attempts_account_idx ON login_attempts (account_id) WHERE account_id IS NOT NULL;
CREATE INDEX login_attempts_ip_idx ON login_attempts (ip) WHERE ip IS NOT NULL;
CREATE INDEX login_attempts_locked_until_idx ON login_attempts (locked_until) WHERE locked_until IS NOT NULL;

CREATE TRIGGER login_attempts_set_updated_at
BEFORE UPDATE ON login_attempts
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
