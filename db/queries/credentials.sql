-- name: CreateCredential :one
INSERT INTO credentials (
    id,
    account_id,
    kind,
    provider,
    external_subject,
    display_name,
    verified
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.arg(kind),
    sqlc.narg(provider),
    sqlc.narg(external_subject),
    sqlc.arg(display_name),
    sqlc.arg(verified)
)
RETURNING *;

-- name: GetCredentialByID :one
SELECT *
FROM credentials
WHERE id = sqlc.arg(id);

-- name: ListCredentialsByAccount :many
SELECT *
FROM credentials
WHERE account_id = sqlc.arg(account_id)
  AND revoked_at IS NULL
ORDER BY created_at ASC;

-- name: ListCredentialsByAccountAndKind :many
SELECT *
FROM credentials
WHERE account_id = sqlc.arg(account_id)
  AND kind = sqlc.arg(kind)
  AND revoked_at IS NULL
ORDER BY created_at ASC;

-- name: GetCredentialByAccountKindProvider :one
SELECT *
FROM credentials
WHERE account_id = sqlc.arg(account_id)
  AND kind = sqlc.arg(kind)
  AND provider IS NOT DISTINCT FROM sqlc.narg(provider)
  AND revoked_at IS NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: GetCredentialByProviderSubject :one
SELECT *
FROM credentials
WHERE kind = sqlc.arg(kind)
  AND provider = sqlc.arg(provider)
  AND external_subject = sqlc.arg(external_subject)
  AND revoked_at IS NULL;

-- name: GetCredentialPayload :one
SELECT *
FROM credential_payloads
WHERE credential_id = sqlc.arg(credential_id);

-- name: UpsertCredentialPayload :one
INSERT INTO credential_payloads (
    credential_id,
    algorithm,
    key_ref,
    nonce,
    ciphertext,
    aad,
    version
) VALUES (
    sqlc.arg(credential_id),
    sqlc.arg(algorithm),
    sqlc.arg(key_ref),
    sqlc.narg(nonce),
    sqlc.arg(ciphertext),
    sqlc.arg(aad),
    sqlc.arg(version)
)
ON CONFLICT (credential_id) DO UPDATE
SET algorithm = EXCLUDED.algorithm,
    key_ref = EXCLUDED.key_ref,
    nonce = EXCLUDED.nonce,
    ciphertext = EXCLUDED.ciphertext,
    aad = EXCLUDED.aad,
    version = EXCLUDED.version
RETURNING *;

-- name: UpdateCredentialLastUsed :one
UPDATE credentials
SET last_used_at = sqlc.arg(last_used_at)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: UpdateCredentialState :one
UPDATE credentials
SET verified = COALESCE(sqlc.narg(verified), verified),
    last_used_at = COALESCE(sqlc.narg(last_used_at), last_used_at)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: RevokeCredential :one
UPDATE credentials
SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL
RETURNING *;
