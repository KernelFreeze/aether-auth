CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL CHECK (slug <> ''),
    slug_normalized TEXT NOT NULL CHECK (slug_normalized = lower(slug_normalized)),
    name TEXT NOT NULL CHECK (name <> ''),
    mfa_required BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX organizations_slug_normalized_key ON organizations (slug_normalized);

CREATE TRIGGER organizations_set_updated_at
BEFORE UPDATE ON organizations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE memberships (
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    invited_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, organization_id)
);

CREATE INDEX memberships_organization_role_idx ON memberships (organization_id, role);

CREATE TRIGGER memberships_set_updated_at
BEFORE UPDATE ON memberships
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email_normalized TEXT NOT NULL CHECK (email_normalized = lower(email_normalized)),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    token_hash BYTEA NOT NULL,
    invited_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    accepted_by UUID REFERENCES accounts (id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX invitations_token_hash_key ON invitations (token_hash);
CREATE INDEX invitations_open_email_idx
    ON invitations (organization_id, email_normalized)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TRIGGER invitations_set_updated_at
BEFORE UPDATE ON invitations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
