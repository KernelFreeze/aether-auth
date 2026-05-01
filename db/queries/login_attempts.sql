-- name: GetLoginAttempt :one
SELECT *
FROM login_attempts
WHERE endpoint = sqlc.arg(endpoint)
  AND subject_type = sqlc.arg(subject_type)
  AND subject_hash = sqlc.arg(subject_hash);

-- name: RecordLoginFailure :one
INSERT INTO login_attempts (
    id,
    endpoint,
    subject_type,
    subject_hash,
    account_id,
    username_normalized,
    ip,
    failed_count,
    locked_until,
    last_failed_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(endpoint),
    sqlc.arg(subject_type),
    sqlc.arg(subject_hash),
    sqlc.narg(account_id),
    sqlc.narg(username_normalized),
    sqlc.narg(ip),
    1,
    CASE
        WHEN 1 >= sqlc.arg(max_failures)::integer THEN sqlc.arg(lock_until)
        ELSE NULL
    END,
    sqlc.arg(occurred_at)
)
ON CONFLICT (endpoint, subject_type, subject_hash) DO UPDATE
SET account_id = COALESCE(EXCLUDED.account_id, login_attempts.account_id),
    username_normalized = COALESCE(EXCLUDED.username_normalized, login_attempts.username_normalized),
    ip = COALESCE(EXCLUDED.ip, login_attempts.ip),
    failed_count = login_attempts.failed_count + 1,
    locked_until = CASE
        WHEN login_attempts.failed_count + 1 >= sqlc.arg(max_failures)::integer THEN sqlc.arg(lock_until)
        ELSE login_attempts.locked_until
    END,
    last_failed_at = sqlc.arg(occurred_at)
RETURNING *;

-- name: RecordLoginSuccess :one
UPDATE login_attempts
SET failed_count = 0,
    locked_until = NULL,
    last_success_at = sqlc.arg(occurred_at)
WHERE endpoint = sqlc.arg(endpoint)
  AND subject_type = sqlc.arg(subject_type)
  AND subject_hash = sqlc.arg(subject_hash)
RETURNING *;

-- name: LockLoginAttemptUntil :one
UPDATE login_attempts
SET locked_until = sqlc.arg(locked_until)
WHERE endpoint = sqlc.arg(endpoint)
  AND subject_type = sqlc.arg(subject_type)
  AND subject_hash = sqlc.arg(subject_hash)
RETURNING *;

-- name: ClearExpiredLoginAttemptLocks :execrows
UPDATE login_attempts
SET locked_until = NULL
WHERE locked_until IS NOT NULL
  AND locked_until <= sqlc.arg(expired_at);
