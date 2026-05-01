-- name: CreateAccount :one
INSERT INTO accounts (
    id,
    username,
    username_normalized,
    display_name,
    disabled,
    mfa_required,
    locked_until,
    metadata
) VALUES (
    sqlc.arg(id),
    sqlc.arg(username),
    sqlc.arg(username_normalized),
    sqlc.arg(display_name),
    sqlc.arg(disabled),
    sqlc.arg(mfa_required),
    sqlc.narg(locked_until),
    sqlc.arg(metadata)
)
RETURNING *;

-- name: GetAccountByID :one
SELECT *
FROM accounts
WHERE id = sqlc.arg(id);

-- name: GetAccountByUsername :one
SELECT *
FROM accounts
WHERE username_normalized = sqlc.arg(username_normalized);

-- name: GetAccountByEmail :one
SELECT a.*
FROM accounts AS a
JOIN emails AS e ON e.account_id = a.id
WHERE e.address_normalized = sqlc.arg(address_normalized);

-- name: UpdateAccountLockout :one
UPDATE accounts
SET locked_until = sqlc.narg(locked_until)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: CreateEmail :one
INSERT INTO emails (
    id,
    account_id,
    address,
    address_normalized,
    verified,
    is_primary,
    verified_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.arg(address),
    sqlc.arg(address_normalized),
    sqlc.arg(verified),
    sqlc.arg(is_primary),
    sqlc.narg(verified_at)
)
RETURNING *;

-- name: ListEmailsByAccount :many
SELECT *
FROM emails
WHERE account_id = sqlc.arg(account_id)
ORDER BY is_primary DESC, created_at ASC;
