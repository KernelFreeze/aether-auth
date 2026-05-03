-- name: CreateRecoveryCode :one
INSERT INTO recovery_codes (
    id,
    account_id,
    credential_id,
    code_hash
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.arg(credential_id),
    sqlc.arg(code_hash)
)
RETURNING *;

-- name: ListUnusedRecoveryCodes :many
SELECT *
FROM recovery_codes
WHERE account_id = sqlc.arg(account_id)
  AND credential_id = sqlc.arg(credential_id)
  AND used_at IS NULL
ORDER BY created_at ASC;

-- name: ConsumeRecoveryCode :one
UPDATE recovery_codes
SET used_at = sqlc.arg(used_at)
WHERE id = sqlc.arg(id)
  AND account_id = sqlc.arg(account_id)
  AND credential_id = sqlc.arg(credential_id)
  AND used_at IS NULL
RETURNING *;

-- name: DeleteUnusedRecoveryCodes :execrows
DELETE FROM recovery_codes
WHERE account_id = sqlc.arg(account_id)
  AND credential_id = sqlc.arg(credential_id)
  AND used_at IS NULL;
