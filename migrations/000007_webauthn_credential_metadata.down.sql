ALTER TABLE webauthn_credentials
    DROP COLUMN authenticator_attachment,
    DROP COLUMN backup_eligible,
    DROP COLUMN transports;
