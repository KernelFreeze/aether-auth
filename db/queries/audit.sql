-- name: AppendAuditEvent :one
INSERT INTO audit_events (
    id,
    event_type,
    account_id,
    credential_id,
    session_id,
    client_id,
    organization_id,
    request_id,
    ip,
    user_agent,
    occurred_at,
    attributes
) VALUES (
    sqlc.arg(id),
    sqlc.arg(event_type),
    sqlc.narg(account_id),
    sqlc.narg(credential_id),
    sqlc.narg(session_id),
    sqlc.narg(client_id),
    sqlc.narg(organization_id),
    sqlc.arg(request_id),
    sqlc.narg(ip),
    sqlc.arg(user_agent),
    sqlc.arg(occurred_at),
    sqlc.arg(attributes)
)
RETURNING *;

-- name: ListRecentLoginAuditEvents :many
SELECT *
FROM audit_events
WHERE account_id = sqlc.arg(account_id)
  AND event_type = ANY(sqlc.arg(event_types)::text[])
ORDER BY occurred_at DESC
LIMIT sqlc.arg(row_limit);
