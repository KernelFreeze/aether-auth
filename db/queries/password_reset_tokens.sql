-- name: GetPasswordResetTargetByUsername :one
SELECT
    a.id,
    a.username,
    a.username_normalized,
    e.address AS email_address,
    e.address_normalized AS email_normalized
FROM accounts AS a
JOIN emails AS e ON e.account_id = a.id
WHERE a.username_normalized = sqlc.arg(username_normalized)
  AND e.is_primary = true
ORDER BY e.created_at ASC
LIMIT 1;

-- name: GetPasswordResetTargetByEmail :one
SELECT
    a.id,
    a.username,
    a.username_normalized,
    e.address AS email_address,
    e.address_normalized AS email_normalized
FROM emails AS e
JOIN accounts AS a ON a.id = e.account_id
WHERE e.address_normalized = sqlc.arg(email_normalized)
ORDER BY e.is_primary DESC, e.created_at ASC
LIMIT 1;

-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (
    id,
    account_id,
    token_hash,
    requested_by_ip,
    user_agent,
    expires_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.arg(token_hash),
    sqlc.narg(requested_by_ip),
    sqlc.arg(user_agent),
    sqlc.arg(expires_at)
)
RETURNING *;
