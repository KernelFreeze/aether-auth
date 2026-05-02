-- name: UpsertSessionUserAgent :one
INSERT INTO session_user_agents (
    fingerprint_id,
    ip,
    description,
    headers
) VALUES (
    sqlc.arg(fingerprint_id),
    sqlc.narg(ip),
    sqlc.arg(description),
    sqlc.arg(headers)
)
ON CONFLICT (fingerprint_id) DO UPDATE
SET ip = EXCLUDED.ip,
    description = EXCLUDED.description,
    headers = EXCLUDED.headers
RETURNING *;

-- name: CreateSession :one
INSERT INTO sessions (
    id,
    account_id,
    client_id,
    kind,
    status,
    token_id,
    user_agent_id,
    ip,
    expires_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(account_id),
    sqlc.narg(client_id),
    sqlc.arg(kind),
    sqlc.arg(status),
    sqlc.narg(token_id),
    sqlc.narg(user_agent_id),
    sqlc.narg(ip),
    sqlc.arg(expires_at)
)
RETURNING *;

-- name: GetSessionByID :one
SELECT *
FROM sessions
WHERE id = sqlc.arg(id);

-- name: GetActiveSessionByID :one
SELECT *
FROM sessions
WHERE id = sqlc.arg(id)
  AND kind = 'full'
  AND status = 'active'
  AND expires_at > sqlc.arg(active_at);

-- name: ListSessionsByAccount :many
SELECT *
FROM sessions
WHERE account_id = sqlc.arg(account_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit);

-- name: ListActiveSessionsByAccount :many
SELECT *
FROM sessions
WHERE account_id = sqlc.arg(account_id)
  AND status = 'active'
  AND expires_at > sqlc.arg(active_at)
ORDER BY created_at DESC;

-- name: RevokeSession :one
UPDATE sessions
SET status = 'revoked',
    revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id)
  AND status = 'active'
RETURNING *;

-- name: RevokeSessionForAccount :one
UPDATE sessions
SET status = 'revoked',
    revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id)
  AND account_id = sqlc.arg(account_id)
  AND status = 'active'
RETURNING *;

-- name: RevokeSessionsByAccount :many
UPDATE sessions
SET status = 'revoked',
    revoked_at = sqlc.arg(revoked_at)
WHERE account_id = sqlc.arg(account_id)
  AND kind = 'full'
  AND status = 'active'
RETURNING *;

-- name: UpdateSessionAccessToken :one
UPDATE sessions
SET token_id = sqlc.arg(token_id)
WHERE id = sqlc.arg(id)
  AND kind = 'full'
  AND status = 'active'
RETURNING *;

-- name: CreateSessionFactor :one
INSERT INTO session_factors (
    session_id,
    factor_kind,
    challenge_binding,
    verified_at,
    metadata
) VALUES (
    sqlc.arg(session_id),
    sqlc.arg(factor_kind),
    sqlc.arg(challenge_binding),
    sqlc.arg(verified_at),
    sqlc.arg(metadata)
)
ON CONFLICT (session_id, factor_kind) DO UPDATE
SET challenge_binding = EXCLUDED.challenge_binding,
    verified_at = EXCLUDED.verified_at,
    metadata = EXCLUDED.metadata
RETURNING *;

-- name: ListSessionFactors :many
SELECT *
FROM session_factors
WHERE session_id = sqlc.arg(session_id)
ORDER BY verified_at ASC;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    id,
    session_id,
    parent_id,
    client_id,
    token_hash,
    scopes,
    expires_at,
    absolute_expires_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(session_id),
    sqlc.narg(parent_id),
    sqlc.narg(client_id),
    sqlc.arg(token_hash),
    sqlc.arg(scopes),
    sqlc.arg(expires_at),
    sqlc.arg(absolute_expires_at)
)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT *
FROM refresh_tokens
WHERE token_hash = sqlc.arg(token_hash);

-- name: RotateRefreshToken :one
UPDATE refresh_tokens
SET rotated_at = sqlc.arg(rotated_at)
WHERE id = sqlc.arg(id)
  AND rotated_at IS NULL
  AND revoked_at IS NULL
RETURNING *;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL
RETURNING *;

-- name: RevokeRefreshTokensBySession :many
UPDATE refresh_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE session_id = sqlc.arg(session_id)
  AND revoked_at IS NULL
RETURNING *;

-- name: RevokeRefreshTokensByAccount :many
UPDATE refresh_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE session_id IN (
    SELECT id
    FROM sessions
    WHERE account_id = sqlc.arg(account_id)
)
  AND revoked_at IS NULL
RETURNING *;

-- name: RevokeRefreshTokenChain :many
WITH RECURSIVE token_ancestors AS (
    SELECT refresh_tokens.id, refresh_tokens.parent_id
    FROM refresh_tokens
    WHERE refresh_tokens.id = sqlc.arg(root_id)

    UNION ALL

    SELECT rt.id, rt.parent_id
    FROM refresh_tokens AS rt
    JOIN token_ancestors AS ta ON ta.parent_id = rt.id
),
token_chain AS (
    SELECT id
    FROM token_ancestors

    UNION ALL

    SELECT rt.id
    FROM refresh_tokens AS rt
    JOIN token_chain AS tc ON rt.parent_id = tc.id
)
UPDATE refresh_tokens
SET revoked_at = sqlc.arg(revoked_at)
WHERE id IN (SELECT id FROM token_chain)
  AND revoked_at IS NULL
RETURNING *;
