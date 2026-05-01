CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL CHECK (event_type <> ''),
    account_id UUID REFERENCES accounts (id) ON DELETE SET NULL,
    credential_id UUID REFERENCES credentials (id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    client_id UUID REFERENCES oauth_clients (id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations (id) ON DELETE SET NULL,
    request_id TEXT NOT NULL DEFAULT '',
    ip INET,
    user_agent TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_account_time_idx ON audit_events (account_id, occurred_at DESC) WHERE account_id IS NOT NULL;
CREATE INDEX audit_events_credential_time_idx ON audit_events (credential_id, occurred_at DESC) WHERE credential_id IS NOT NULL;
CREATE INDEX audit_events_session_time_idx ON audit_events (session_id, occurred_at DESC) WHERE session_id IS NOT NULL;
CREATE INDEX audit_events_client_time_idx ON audit_events (client_id, occurred_at DESC) WHERE client_id IS NOT NULL;
CREATE INDEX audit_events_org_time_idx ON audit_events (organization_id, occurred_at DESC) WHERE organization_id IS NOT NULL;
CREATE INDEX audit_events_type_time_idx ON audit_events (event_type, occurred_at DESC);
