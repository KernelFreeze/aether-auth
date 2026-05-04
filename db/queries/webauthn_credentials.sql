-- name: CreateWebAuthnCredential :one
INSERT INTO webauthn_credentials (
    credential_id,
    key_id,
    public_key,
    sign_count,
    relying_party_id,
    aaguid,
    attestation_type,
    user_verified,
    backed_up,
    transports,
    backup_eligible,
    authenticator_attachment
) VALUES (
    sqlc.arg(credential_id),
    sqlc.arg(key_id),
    sqlc.arg(public_key),
    sqlc.arg(sign_count),
    sqlc.arg(relying_party_id),
    sqlc.narg(aaguid),
    sqlc.arg(attestation_type),
    sqlc.arg(user_verified),
    sqlc.arg(backed_up),
    sqlc.arg(transports),
    sqlc.arg(backup_eligible),
    sqlc.arg(authenticator_attachment)
)
RETURNING *;

-- name: GetWebAuthnCredentialByCredentialID :one
SELECT sqlc.embed(c), sqlc.embed(wc)
FROM credentials AS c
JOIN webauthn_credentials AS wc ON wc.credential_id = c.id
WHERE c.id = sqlc.arg(credential_id)
  AND c.kind = 'webauthn'
  AND c.revoked_at IS NULL;

-- name: GetWebAuthnCredentialByKeyID :one
SELECT sqlc.embed(c), sqlc.embed(wc)
FROM credentials AS c
JOIN webauthn_credentials AS wc ON wc.credential_id = c.id
WHERE wc.key_id = sqlc.arg(key_id)
  AND c.kind = 'webauthn'
  AND c.revoked_at IS NULL;

-- name: ListWebAuthnCredentialsByAccount :many
SELECT sqlc.embed(c), sqlc.embed(wc)
FROM credentials AS c
JOIN webauthn_credentials AS wc ON wc.credential_id = c.id
WHERE c.account_id = sqlc.arg(account_id)
  AND c.kind = 'webauthn'
  AND c.revoked_at IS NULL
  AND (sqlc.arg(relying_party_id)::text = '' OR wc.relying_party_id = sqlc.arg(relying_party_id))
ORDER BY c.created_at ASC;

-- name: UpdateWebAuthnCredentialAssertion :one
UPDATE webauthn_credentials
SET sign_count = sqlc.arg(sign_count),
    user_verified = sqlc.arg(user_verified),
    backed_up = sqlc.arg(backed_up),
    transports = sqlc.arg(transports),
    backup_eligible = sqlc.arg(backup_eligible),
    authenticator_attachment = sqlc.arg(authenticator_attachment)
WHERE credential_id = sqlc.arg(credential_id)
RETURNING *;
