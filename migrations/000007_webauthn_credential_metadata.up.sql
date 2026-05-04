ALTER TABLE webauthn_credentials
    ADD COLUMN transports TEXT[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN backup_eligible BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN authenticator_attachment TEXT NOT NULL DEFAULT '';
