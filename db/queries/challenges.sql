-- name: CreateAuthChallenge :one
INSERT INTO auth_challenges (
    id,
    purpose,
    account_id,
    credential_id,
    provider,
    session_binding,
    request_id,
    payload,
    expires_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(purpose),
    sqlc.narg(account_id),
    sqlc.narg(credential_id),
    sqlc.narg(provider),
    sqlc.arg(session_binding),
    sqlc.arg(request_id),
    sqlc.arg(payload),
    sqlc.arg(expires_at)
)
RETURNING *;

-- name: GetAuthChallenge :one
SELECT *
FROM auth_challenges
WHERE id = sqlc.arg(id);

-- name: ConsumeAuthChallenge :one
UPDATE auth_challenges
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(consumed_at)
RETURNING *;

-- name: ListExpiredAuthChallenges :many
SELECT *
FROM auth_challenges
WHERE expires_at <= sqlc.arg(expired_at)
ORDER BY expires_at ASC
LIMIT sqlc.arg(row_limit);

-- name: DeleteExpiredAuthChallenges :execrows
DELETE FROM auth_challenges
WHERE expires_at <= sqlc.arg(expired_at);

-- name: DeleteAuthChallenge :execrows
DELETE FROM auth_challenges
WHERE id = sqlc.arg(id);

-- name: CreateOIDCPendingState :one
INSERT INTO oidc_pending_states (
    id,
    provider,
    session_binding,
    state_hash,
    nonce_hash,
    pkce_verifier_ciphertext,
    redirect_uri,
    expires_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(provider),
    sqlc.arg(session_binding),
    sqlc.arg(state_hash),
    sqlc.narg(nonce_hash),
    sqlc.narg(pkce_verifier_ciphertext),
    sqlc.arg(redirect_uri),
    sqlc.arg(expires_at)
)
RETURNING *;

-- name: ConsumeOIDCPendingState :one
UPDATE oidc_pending_states
SET consumed_at = sqlc.arg(consumed_at)
WHERE provider = sqlc.arg(provider)
  AND state_hash = sqlc.arg(state_hash)
  AND consumed_at IS NULL
  AND expires_at > sqlc.arg(consumed_at)
RETURNING *;

-- name: DeleteExpiredOIDCPendingStates :execrows
DELETE FROM oidc_pending_states
WHERE expires_at <= sqlc.arg(expired_at);
