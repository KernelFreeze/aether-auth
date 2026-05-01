# Zitadel reuse list

Files and components from the Zitadel checkout at
`~/Documents/Development/CelesteLove/zitadel` planned for reuse in Aether.
See `docs/ZITADEL_REUSE.md` for rationale, porting notes, and what to avoid.

## WebAuthn and passkeys

Target: `internal/auth/webauthn`.

- `internal/webauthn/webauthn.go`
- `internal/webauthn/converter.go`
- `internal/webauthn/client.go`
- `backend/v3/domain/passkey.go`
- `backend/v3/domain/session_challenge_passkey.go`
- `backend/v3/domain/session_check_passkey.go`

## External OIDC login

Target: `internal/auth/oidc`.

- `internal/idp/providers/oidc/oidc.go`
- `internal/idp/providers/oidc/session.go`
- `internal/idp/providers/oidc/oidc_test.go`

## Session factors and MFA state

Target: `internal/session`, `internal/mfa`.

- `backend/v3/domain/session_factor.go`
- `backend/v3/domain/session_check_user.go`
- `backend/v3/domain/session_check_password.go`
- `backend/v3/domain/session_check_totp.go`
- `backend/v3/domain/session_check_recovery_code.go`
- `backend/v3/domain/session_challenge_passkey.go`

## Password verification and lockout

- `backend/v3/domain/session_check_password.go`
- `internal/command/user_human_password.go`
- `internal/command/user_human_password_test.go`

## TOTP and recovery codes

- `internal/domain/human_otp.go`
- `internal/domain/human_recovery_codes.go`
- `internal/command/user_human_otp.go`
- `internal/command/user_human_recovery_codes.go`
- `backend/v3/domain/session_check_totp.go`
- `backend/v3/domain/session_check_recovery_code.go`

## Schema references

- `backend/v3/storage/database/dialect/postgres/migration/011_session_table/up.sql`
- `backend/v3/storage/database/dialect/postgres/migration/013_user_table/up.sql`
- `backend/v3/storage/database/dialect/postgres/migration/017_archived_sessions_table/up.sql`

## Error handling

- `internal/zerrors` — reference for typed error kinds, stable error IDs, parent
  errors, and structured details.

## Tests as behavior specs

- `internal/webauthn/client.go` — browserless passkey tests.
- `internal/idp/providers/oidc/oidc_test.go` — mocked OIDC discovery and PKCE.
- `backend/v3/domain/session_check_password_test.go` — lockout and failed
  password behavior.
- `backend/v3/domain/session_check_totp_test.go` — TOTP failure behavior.
- `backend/v3/domain/session_check_recovery_code_test.go` — recovery code
  behavior.
