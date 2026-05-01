# Aether Auth TODO

This TODO is ordered by dependency, not by feature appeal. The first stages
define the contracts, storage, and security invariants that every auth method
needs. Zitadel reuse starts only after those contracts exist, so copied or
ported code can fit Aether's Gin, sqlc, PASETO, and feature-module structure.

When copying code from Zitadel, keep AGPL-3.0-only compatibility, attribution,
SPDX headers when present, and a short note in the destination package naming
the source file. Prefer small ports over importing Zitadel's command/query and
eventstore architecture.

## Stage 1: Shared auth contracts and common interfaces

This stage must land before password, WebAuthn, OIDC, TOTP, MFA, sessions, or
OAuth2 work. The goal is to make every auth method look like a plug-in to the
orchestrator while still allowing method-specific challenge flows.

- [x] Create shared domain types for identity and credentials, likely under
  `internal/account` or a small shared package:
  - [x] `AccountID`, `CredentialID`, `SessionID`, `OrganizationID`, and
    `ClientID` wrappers or documented UUID aliases.
  - [x] `CredentialKind` values: `password`, `webauthn`, `oidc`, `totp`,
    `recovery_code`.
  - [x] `FactorKind` values: `user`, `password`, `passkey`, `idp`, `totp`,
    `recovery_code`.
  - [x] Shared timestamp and expiry conventions.
- [x] Define the core `AuthMethod` interface before implementing any method.
  It should cover both immediate methods such as password and challenge-based
  methods such as WebAuthn and OIDC.
  - [x] `Kind() CredentialKind`.
  - [x] `Begin(ctx, BeginRequest) (BeginResult, error)` for challenge,
    redirect, or no-op setup.
  - [x] `Verify(ctx, VerifyRequest) (AuthResult, error)` for credential
    verification.
  - [x] Document which methods may create, link, or only verify credentials.
- [x] Define request/result structs used by every auth method:
  - [x] `BeginRequest`: username, account hint, provider, redirect URI, user
    agent, IP, session/challenge binding, and trace-safe request ID.
  - [x] `BeginResult`: challenge payload, redirect URL, challenge ID, expiry,
    and public metadata safe to send to clients.
  - [x] `VerifyRequest`: credential input, challenge ID, account hint, IP, user
    agent, and current partial session if present.
  - [x] `AuthResult`: account ID, credential ID, verified factors, MFA status,
    external identity data, audit metadata, and session issue instructions.
- [ ] Define cross-feature interfaces with small method sets:
  - [ ] `AccountRepository` for account lookup and state checks.
  - [ ] `CredentialRepository` for credential lookup, create, update, and
    last-credential safety checks.
  - [ ] `ChallengeStore` for WebAuthn, OIDC state, nonce, PKCE, and one-time
    challenge TTLs.
  - [ ] `FactorStore` for partial-session factor state.
  - [ ] `SessionIssuer` for partial and full session creation.
  - [ ] `AuditWriter` for security events.
  - [ ] `RateLimiter` for IP, account, and endpoint limits.
  - [ ] `Clock`, `RandomReader`, and `IDGenerator` for deterministic tests.
  - [ ] `PasswordHasher`, `PasswordPolicy`, and `BreachChecker`.
  - [ ] `SecretBox` or `Encryptor` for AES-256-GCM encrypted credential data.
- [ ] Define typed service errors before handlers exist:
  - [ ] Internal error kinds for invalid credentials, locked account, expired
    challenge, replayed challenge, malformed input, provider failure,
    insufficient scope, and policy denial.
  - [ ] Public error mapping with generic login and reset responses.
  - [ ] `application/problem+json` helpers in `internal/platform/httpx`.
  - [ ] A stable place for error IDs if Zitadel's `internal/zerrors` model is
    adapted.
- [ ] Define module wiring conventions:
  - [ ] Every feature exposes `Module`, `Deps`, `New(deps)`, and
    `RegisterRoutes`.
  - [ ] `internal/httpapi/router.go` remains the only complete URL map.
  - [ ] No feature package reads global config or opens its own DB, Redis,
    mailer, queue, or logger.
- [ ] Add unit tests for interface-level behavior:
  - [ ] Fake `AuthMethod` implementations can be registered and called by the
    orchestrator.
  - [ ] Public error mapping never leaks account existence.
  - [ ] Clock and random fakes make challenge expiry tests deterministic.

Exit criteria:

- [ ] A skeleton auth orchestrator can register at least two fake methods.
- [ ] `just test` passes without external services.
- [ ] New interfaces are documented enough that password and WebAuthn can be
  implemented without changing their shape.

## Stage 2: Persistence foundation

This stage gives every later feature stable storage. Translate Zitadel schema
ideas into Aether migrations and sqlc queries; do not copy Zitadel's dynamic
repository layer.

- [ ] Add initial migrations in dependency order:
  - [ ] Accounts, emails, credentials.
  - [ ] Credential encrypted payload metadata.
  - [ ] Login attempts and lockout state.
  - [ ] Sessions, refresh tokens, partial sessions, and session factors.
  - [ ] WebAuthn challenges and credentials if not stored in generic
    credential payloads.
  - [ ] OIDC provider links and pending OIDC states.
  - [ ] TOTP credentials and recovery-code hashes.
  - [ ] Password reset tokens.
  - [ ] OAuth clients, authorization codes, consent grants, and OAuth refresh
    tokens.
  - [ ] Organizations, memberships, and invitations.
  - [ ] Audit log.
- [ ] Use Zitadel schema references for shape and indexes:
  - [ ] `backend/v3/storage/database/dialect/postgres/migration/011_session_table/up.sql`.
  - [ ] `backend/v3/storage/database/dialect/postgres/migration/013_user_table/up.sql`.
  - [ ] `backend/v3/storage/database/dialect/postgres/migration/017_archived_sessions_table/up.sql`.
- [ ] Add sqlc query files under `db/queries/`:
  - [ ] Account lookup by username, email, ID.
  - [ ] Credential lookup by account, kind, provider, credential ID, and
    external subject.
  - [ ] Challenge insert, consume, expire, and delete.
  - [ ] Login attempt update and lockout calculation.
  - [ ] Session create, list, revoke, rotate refresh token, and revoke chain.
  - [ ] Audit append and recent login query.
- [ ] Regenerate sqlc output with `just sqlc`.
- [ ] Add repository wrappers that depend on `sqlc.Queries`, not raw SQL in
  handlers.
- [ ] Add integration tests behind `//go:build integration` for migrations and
  repository behavior.

Exit criteria:

- [ ] `just sqlc` succeeds.
- [ ] `just test` still avoids integration tests.
- [ ] `just test-integration` covers the first repository batch when Postgres
  is available.

## Stage 3: Platform primitives

- [ ] Finish `internal/platform/crypto`:
  - [ ] Argon2id PHC-string encode, parse, verify, and needs-rehash helpers.
  - [ ] HMAC-SHA-256 pepper pre-hash for passwords.
  - [ ] AES-256-GCM seal/open helpers for credential payloads.
  - [ ] CSPRNG helpers with unbiased random string generation.
  - [ ] Constant-time comparison helpers where needed.
- [ ] Finish `internal/platform/paseto`:
  - [ ] Load Ed25519 signing keys from secret refs.
  - [ ] Load v4.local symmetric keys from secret refs.
  - [ ] Issue and verify v4.public access tokens.
  - [ ] Issue and verify v4.local partial-session tokens.
  - [ ] Support `kid` footers and implicit assertions.
- [ ] Finish `internal/platform/keys`:
  - [ ] Public key endpoint format for `/.well-known/paseto-keys`.
  - [ ] Key rotation schedule and overlap window.
  - [ ] Worker task or cron registration for rotation.
- [ ] Finish `internal/platform/httpx`:
  - [ ] Problem response helpers.
  - [ ] Generic auth failure helpers.
  - [ ] Timing equalizer helper for login and reset flows.
- [ ] Finish `internal/ratelimit`:
  - [ ] Redis-backed IP, account, and endpoint buckets.
  - [ ] Middleware hooks usable before auth verification.
  - [ ] Unit tests with fake limiter and integration tests with Redis.
- [ ] Add test helpers under `internal/testutil`:
  - [ ] Fake clock.
  - [ ] Deterministic random reader.
  - [ ] JSON assertion helper for Gin handlers.
  - [ ] Config builder with safe defaults.
  - [ ] Repository integration harness.

Exit criteria:

- [ ] Crypto helpers have table-driven tests and invalid-input tests.
- [ ] PASETO keystore is no longer a stub.
- [ ] The public key endpoint returns active verification keys.

## Stage 4: Account and credential core

- [ ] Implement account registration service:
  - [ ] Username normalization and validation.
  - [ ] Email normalization, uniqueness, and optional verification state.
  - [ ] Anti-enumeration behavior when username or email is already taken.
  - [ ] Audit events for registration attempts.
- [ ] Implement credential management:
  - [ ] Generic credential create, read, update, delete.
  - [ ] Encrypted credential payload serialization.
  - [ ] Provider-specific uniqueness for OIDC credentials.
  - [ ] Last-credential removal protection.
  - [ ] Re-authentication requirement for destructive credential changes.
- [ ] Add account settings routes:
  - [ ] Read profile.
  - [ ] Update display name or profile metadata.
  - [ ] List credentials without exposing secrets.
  - [ ] Remove credential when policy allows it.
- [ ] Add repository and handler tests:
  - [ ] Duplicate username and duplicate email behavior.
  - [ ] Last credential cannot be removed.
  - [ ] Public responses do not reveal whether an account exists.

Exit criteria:

- [ ] Accounts and credentials can be created without sessions.
- [ ] Credential payloads are encrypted at rest.
- [ ] Account APIs are mounted through `internal/httpapi/router.go`.

## Stage 5: Auth orchestrator and password auth

This is the first real `AuthMethod` implementation. Use Zitadel's password
state-transition tests as references, but keep Aether's NIST/OWASP password
policy.

- [ ] Implement `internal/auth` orchestrator:
  - [ ] Register `AuthMethod` implementations by `CredentialKind`.
  - [ ] Enforce rate limiting before credential verification.
  - [ ] Normalize public login errors to `invalid_credentials`.
  - [ ] Run dummy password work for missing accounts.
  - [ ] Apply timing equalization on success, failure, and lockout paths.
  - [ ] Emit audit events for success and failure.
- [ ] Implement `internal/auth/password`:
  - [ ] Password set/change with policy checks.
  - [ ] HIBP k-anonymity breach check with Redis cache.
  - [ ] Argon2id hash with pepper.
  - [ ] Password verification outside DB transactions.
  - [ ] Rehash on login when parameters change.
- [ ] Reuse or port from Zitadel:
  - [ ] `backend/v3/domain/session_check_password.go` for the factor update
    model.
  - [ ] `internal/command/user_human_password.go` for transaction boundaries
    and lockout flow.
  - [ ] `internal/command/user_human_password_test.go` for failure and lockout
    cases.
- [ ] Keep Aether-specific behavior:
  - [ ] No copied password composition rules.
  - [ ] Generic public errors for wrong username, wrong password, inactive
    account, and lockout.
  - [ ] Forgot-password remains available during lockout.
- [ ] Add route tests for `POST /auth/login` with password credentials.

Exit criteria:

- [ ] Password login can issue either a full session or a partial MFA session.
- [ ] Failed attempts update lockout state in one transaction.
- [ ] Login tests cover wrong username, wrong password, locked account, and
  valid login without distinguishable public errors.

## Stage 6: Session lifecycle and token issuance

- [ ] Implement full session creation:
  - [ ] Generate a 256-bit session ID.
  - [ ] Store only a SHA-256 hash of the session ID.
  - [ ] Persist IP, user agent, expiry, and auth factors.
  - [ ] Issue PASETO v4.public access tokens.
  - [ ] Issue opaque refresh tokens stored as hashes.
- [ ] Implement partial sessions:
  - [ ] v4.local token with two-minute TTL.
  - [ ] Claims limited to MFA verification.
  - [ ] Factor state bound to account and challenge context.
- [ ] Implement refresh rotation:
  - [ ] Rotate refresh token on every use.
  - [ ] Detect reused refresh tokens.
  - [ ] Revoke the whole rotation chain on reuse.
- [ ] Implement session revocation:
  - [ ] User-initiated session deletion.
  - [ ] Password-change revocation.
  - [ ] Admin revocation hook for later organization work.
  - [ ] Redis revocation set keyed by access-token `jti`.
- [ ] Add account session APIs:
  - [ ] `GET /account/sessions`.
  - [ ] `DELETE /account/sessions/{id}`.
- [ ] Add tests:
  - [ ] Access token claims and footers.
  - [ ] Refresh rotation and reuse detection.
  - [ ] Revocation cache TTL.
  - [ ] Partial token cannot authorize normal APIs.

Exit criteria:

- [ ] Password login can produce usable access and refresh tokens.
- [ ] Refresh token reuse terminates the session family.
- [ ] Revoked access-token IDs are rejected by middleware.

## Stage 7: MFA factor model, TOTP, and recovery codes

This stage should start after sessions exist, because MFA uses partial session
tokens and factor state.

- [ ] Implement shared MFA policy:
  - [ ] Account-level `mfa_enforced`.
  - [ ] Organization-level `mfa_required` hook for later org stage.
  - [ ] Required factors derived from account and org policy.
  - [ ] Upgrade from partial session to full session only after required
    factors are verified.
- [ ] Reuse or port Zitadel's session factor model:
  - [ ] `backend/v3/domain/session_factor.go`.
  - [ ] `backend/v3/domain/session_check_user.go`.
  - [ ] `backend/v3/domain/session_check_totp.go`.
  - [ ] `backend/v3/domain/session_check_recovery_code.go`.
- [ ] Implement `internal/auth/totp`:
  - [ ] TOTP enrollment with QR provisioning URI.
  - [ ] Secret encryption with AES-256-GCM.
  - [ ] RFC 6238 verification with one-window tolerance.
  - [ ] Recovery-code generation using unbiased CSPRNG selection.
  - [ ] Recovery-code hashing and single-use consume.
  - [ ] Lockout behavior for repeated MFA failures.
- [ ] Reuse or port Zitadel helpers:
  - [ ] `internal/domain/human_otp.go`.
  - [ ] `internal/domain/human_recovery_codes.go`.
  - [ ] `internal/command/user_human_otp.go`.
  - [ ] `internal/command/user_human_recovery_codes.go`.
- [ ] Do not copy:
  - [ ] Zitadel AES-CFB helpers for encrypted-at-rest data.
  - [ ] Biased random string generation for recovery codes.
- [ ] Add routes:
  - [ ] `POST /auth/mfa/verify`.
  - [ ] TOTP enrollment, confirmation, disable, and recovery-code regenerate
    endpoints under account settings.
- [ ] Add tests:
  - [ ] TOTP clock-window behavior.
  - [ ] Recovery code single-use behavior.
  - [ ] Partial session cannot be upgraded without required factors.
  - [ ] MFA failures are audited without logging raw codes.

Exit criteria:

- [ ] Password plus TOTP can complete a full login flow.
- [ ] Recovery codes are single-use and never stored in plaintext.
- [ ] MFA state is represented as factors, not hard-coded branches.

## Stage 8: WebAuthn and passkeys using Zitadel reuse

This is a high-value reuse stage. Port the wrapper and test helper into
`internal/auth/webauthn`, then adapt the storage to Aether credentials and
session challenges.

- [ ] Reuse or port:
  - [ ] `internal/webauthn/webauthn.go`.
  - [ ] `internal/webauthn/converter.go`.
  - [ ] `internal/webauthn/client.go`.
  - [ ] `backend/v3/domain/passkey.go`.
  - [ ] `backend/v3/domain/session_challenge_passkey.go`.
  - [ ] `backend/v3/domain/session_check_passkey.go`.
- [ ] Replace Zitadel dependencies:
  - [ ] Replace `domain.Human` with Aether account and credential models.
  - [ ] Replace domain context and tracing with Aether logger/request context.
  - [ ] Replace `zerrors` with Aether service errors.
  - [ ] Replace Zitadel repositories with sqlc-backed repositories.
- [ ] Implement registration flow:
  - [ ] Generate options.
  - [ ] Store single-use challenge with TTL.
  - [ ] Verify attestation response.
  - [ ] Persist credential ID, public key, AAGUID, attestation type, sign
    count, relying party ID, user verification state, and display name.
- [ ] Implement login flow:
  - [ ] Generate assertion options.
  - [ ] Store single-use challenge with TTL.
  - [ ] Verify assertion.
  - [ ] Update sign count.
  - [ ] Detect clone warning and emit audit event.
- [ ] Implement WebAuthn as both primary auth and second factor:
  - [ ] Primary passkey login via `AuthMethod`.
  - [ ] MFA passkey verification through the shared factor model.
- [ ] Port the virtual WebAuthn client test helper early:
  - [ ] Registration without a browser.
  - [ ] Assertion without a browser.
  - [ ] Invalid challenge, replay, and sign-count regression cases.

Exit criteria:

- [ ] Passkey registration and login work in tests.
- [ ] Challenge replay is rejected.
- [ ] WebAuthn can satisfy MFA without special-case orchestration code.

## Stage 9: External OIDC login using Zitadel reuse

This stage implements external identity-provider login, not Aether's OAuth2
authorization server.

- [ ] Decide and document the OIDC client library:
  - [ ] Keep `golang.org/x/oauth2` plus `github.com/coreos/go-oidc/v3`, or
  - [ ] Switch to `github.com/zitadel/oidc/v3` and update
    `docs/IMPLEMENTATION.md`.
- [ ] Reuse or port:
  - [ ] `internal/idp/providers/oidc/oidc.go`.
  - [ ] `internal/idp/providers/oidc/session.go`.
  - [ ] `internal/idp/providers/oidc/oidc_test.go`.
- [ ] Implement provider config:
  - [ ] Issuer URL.
  - [ ] Client ID.
  - [ ] Client secret ref.
  - [ ] Redirect URI.
  - [ ] Scopes.
  - [ ] PKCE requirement.
  - [ ] Auto-link and auto-create policy.
- [ ] Implement authorize start:
  - [ ] Always include `openid`.
  - [ ] Generate state, nonce, and PKCE verifier.
  - [ ] Bind state and nonce to the initiating session/challenge record.
  - [ ] Validate redirect URI by exact match.
- [ ] Implement callback:
  - [ ] Validate state.
  - [ ] Exchange code.
  - [ ] Validate ID token issuer, audience, expiry, nonce, and signature.
  - [ ] Fetch userinfo when configured.
  - [ ] Map external `sub` to an OIDC credential.
  - [ ] Apply link, create, or reject policy.
- [ ] Add tests:
  - [ ] Mock discovery and JWKS.
  - [ ] PKCE and nonce validation.
  - [ ] Provider error callback.
  - [ ] Existing linked credential login.
  - [ ] New external identity rejected when auto-create is disabled.

Exit criteria:

- [ ] `/auth/oidc/{provider}/authorize` and callback are mounted.
- [ ] OIDC login returns the same session result shape as password and
  WebAuthn.
- [ ] OIDC public responses do not leak whether an account already exists.

## Stage 10: Password reset and account recovery

- [ ] Implement reset request:
  - [ ] Accept username or email.
  - [ ] Always return the same public message.
  - [ ] Apply rate limiting before lookup.
  - [ ] Generate a 256-bit random token.
  - [ ] Store only SHA-256 token hash.
  - [ ] Use fixed or allowlisted reset URL origin.
  - [ ] Queue reset email through Asynq.
- [ ] Implement reset confirm:
  - [ ] Verify token hash, expiry, and unused state.
  - [ ] Validate password policy and HIBP status.
  - [ ] Store new password hash.
  - [ ] Mark reset token used.
  - [ ] Revoke all sessions.
  - [ ] Emit audit event.
- [ ] Add email templates:
  - [ ] Password reset.
  - [ ] Password changed notification.
  - [ ] Suspicious reset attempt notification when needed for timing parity.
- [ ] Add tests:
  - [ ] Unknown account response parity.
  - [ ] Expired, used, and malformed token handling.
  - [ ] Session revocation on reset.
  - [ ] Referrer policy and host-header safety at handler boundary.

Exit criteria:

- [ ] Reset flow never exposes account existence.
- [ ] Reset confirm revokes old sessions.
- [ ] Email sending is async and tested with a fake queue.

## Stage 11: OAuth2 authorization server

This stage starts after account, session, credential, and consent primitives
are stable. Do not copy Zitadel's full OIDC/OAuth server; use Fosite with
Aether storage and PASETO token strategy.

- [ ] Add Fosite dependencies and storage adapter:
  - [ ] Client lookup.
  - [ ] Authorization code storage.
  - [ ] PKCE binding.
  - [ ] Consent grant lookup and persistence.
  - [ ] Refresh token storage and rotation.
- [ ] Implement OAuth client registry:
  - [ ] Public and confidential clients.
  - [ ] Client secret hashing.
  - [ ] Exact redirect URI allowlist.
  - [ ] Allowed scopes.
  - [ ] First-party consent skip flag.
- [ ] Implement authorization code flow with PKCE:
  - [ ] `GET /oauth/authorize` or documented method choice.
  - [ ] Login handoff when no active session exists.
  - [ ] Consent screen for third-party clients.
  - [ ] Single-use code with 60-second TTL.
  - [ ] Token exchange at `POST /oauth/token`.
- [ ] Implement client credentials grant:
  - [ ] Confidential client authentication.
  - [ ] Service subject claim.
  - [ ] Audience restriction.
  - [ ] Scope limiting.
- [ ] Implement consent management:
  - [ ] List authorized apps.
  - [ ] Revoke consent.
  - [ ] Revoke refresh tokens for the client-account pair.
- [ ] Implement PASETO token strategy for Fosite:
  - [ ] v4.public access tokens.
  - [ ] Opaque refresh tokens.
  - [ ] `kid` footers and `jti` claims.
- [ ] Add tests:
  - [ ] Exact redirect URI matching.
  - [ ] PKCE failure cases.
  - [ ] Scope downscoping.
  - [ ] Refresh rotation.
  - [ ] Consent revoke invalidates refresh tokens.

Exit criteria:

- [ ] A public client can complete auth code plus PKCE.
- [ ] A confidential client can use client credentials with scoped tokens.
- [ ] OAuth tokens use the same session and revocation primitives as direct
  login.

## Stage 12: Organizations and RBAC

- [ ] Implement organization model:
  - [ ] Create organization.
  - [ ] Slug validation and uniqueness.
  - [ ] Memberships with `owner`, `admin`, and `member`.
  - [ ] Last-owner protection.
  - [ ] Organization-level MFA requirement.
- [ ] Implement invitations:
  - [ ] Generate 256-bit invitation token.
  - [ ] Store only token hash.
  - [ ] Seven-day expiry.
  - [ ] Scope invitation to email and role.
  - [ ] Accept flow for existing account and post-registration account.
- [ ] Implement RBAC checks:
  - [ ] Middleware or service helper for minimum role.
  - [ ] Object ownership checks for organization resources.
  - [ ] Token `org_id` and role claim handling.
- [ ] Add routes:
  - [ ] `POST /orgs`.
  - [ ] `POST /orgs/{slug}/invitations`.
  - [ ] `POST /orgs/{slug}/invitations/{token}`.
  - [ ] `DELETE /orgs/{slug}/members/{account_id}`.
  - [ ] `PATCH /orgs/{slug}/members/{account_id}`.
- [ ] Add tests:
  - [ ] Last owner cannot leave or be demoted.
  - [ ] Admin cannot grant owner by accident.
  - [ ] Invitation token is single-use.
  - [ ] Cross-organization access is rejected.

Exit criteria:

- [ ] Organization membership can be used in token claims.
- [ ] RBAC checks happen before handlers mutate organization state.
- [ ] Organization MFA policy feeds the shared MFA stage.

## Stage 13: Audit logging and security event stream

- [ ] Implement audit writer:
  - [ ] Append-only database sink.
  - [ ] Stable event type constants.
  - [ ] Structured metadata without raw secrets.
  - [ ] Hashed attempted username for failed login events.
- [ ] Emit events for:
  - [ ] Login success and failure.
  - [ ] MFA challenge success and failure.
  - [ ] Password change and reset.
  - [ ] Session revoke.
  - [ ] OAuth authorize and consent revoke.
  - [ ] Organization invite, join, remove, and role change.
  - [ ] WebAuthn clone warning or sign-count anomaly.
- [ ] Add recent-account-activity query:
  - [ ] Last login attempts.
  - [ ] Active session list.
  - [ ] Security-sensitive account changes.
- [ ] Add tests:
  - [ ] Expected events are written.
  - [ ] Raw password, TOTP, recovery code, token, and client secret values are
    never recorded.
  - [ ] Failed login username is hashed.

Exit criteria:

- [ ] Security-sensitive features cannot merge without audit expectations in
  tests.
- [ ] Audit data powers account session and recent activity views.

## Stage 14: HTTP security middleware and templates

- [ ] Implement auth middleware:
  - [ ] Bearer token extraction.
  - [ ] PASETO verification.
  - [ ] Issuer, audience, expiry, and `jti` checks.
  - [ ] Scope checks.
  - [ ] Organization claim checks.
- [ ] Implement CSRF protections:
  - [ ] Synchronizer token support for server-rendered forms.
  - [ ] Cookie-to-header support for SPA-style mutating requests.
  - [ ] SameSite and path-scoped refresh cookie behavior.
- [ ] Implement secure headers:
  - [ ] HSTS.
  - [ ] CSP for auth UI pages.
  - [ ] `X-Content-Type-Options: nosniff`.
  - [ ] `frame-ancestors 'none'`.
- [ ] Build minimal server-rendered templates:
  - [ ] Login.
  - [ ] MFA verify.
  - [ ] Consent.
  - [ ] Password reset.
  - [ ] Account sessions.
  - [ ] Authorized apps.
- [ ] Add tests:
  - [ ] Middleware accepts valid tokens and rejects invalid tokens.
  - [ ] Insufficient scope returns `403`.
  - [ ] CSRF missing or mismatch rejects mutating browser requests.
  - [ ] Security headers are present on UI responses.

Exit criteria:

- [ ] Protected routes have a consistent middleware bundle.
- [ ] Browser-facing flows have CSRF and secure headers.
- [ ] Templates do not expose secrets or raw tokens.

## Stage 15: Workers and async operations

- [ ] Define queue task types in `internal/platform/queue/client.go`:
  - [ ] Send email.
  - [ ] Write or ship audit event if async mode is enabled.
  - [ ] Rotate PASETO keys.
  - [ ] Clean expired challenges.
  - [ ] Clean expired reset tokens.
  - [ ] Clean expired OAuth codes.
  - [ ] Prune revoked token cache records if needed.
- [ ] Implement worker handlers under `internal/workers`:
  - [ ] Validate payloads.
  - [ ] Retry transient failures.
  - [ ] Stop retrying permanent failures.
  - [ ] Log without secrets.
- [ ] Register handlers in `cmd/worker/main.go`.
- [ ] Add tests:
  - [ ] Payload validation.
  - [ ] Retry classification.
  - [ ] Mailer fake receives expected message.
  - [ ] Cleanup jobs only delete expired rows.

Exit criteria:

- [ ] Worker boot registers real handlers.
- [ ] Password reset and invitation email flows use async tasks.
- [ ] Key rotation can run without API boot-time side effects.

## Stage 16: End-to-end flows and integration gates

- [ ] Add integration test coverage for:
  - [ ] Account and credential repositories.
  - [ ] Session and refresh token repositories.
  - [ ] Lockout transaction behavior.
  - [ ] OAuth storage adapter.
  - [ ] Organization invitations.
  - [ ] Audit log writes.
- [ ] Add e2e tests under `test/e2e`:
  - [ ] Register with password, verify email if implemented, login, refresh,
    logout.
  - [ ] Password plus TOTP login.
  - [ ] Passkey registration and login using adapted Zitadel virtual client.
  - [ ] External OIDC login against a local mock provider.
  - [ ] OAuth authorization code plus PKCE.
  - [ ] Organization invite accept flow.
- [ ] Add CI checks:
  - [ ] `just test`.
  - [ ] `just lint`.
  - [ ] Migration validation.
  - [ ] Optional integration job with Postgres and Redis services.
  - [ ] Optional e2e job against the podman stack or testcontainers.
- [ ] Add release readiness checks:
  - [ ] Config example covers all required env variables.
  - [ ] `.env.example` has safe local defaults and no real secrets.
  - [ ] Migrations can apply from empty database.
  - [ ] Migrations can roll back one step where practical.
  - [ ] Docs explain local development, tests, and security-sensitive config.

Exit criteria:

- [ ] `just build` succeeds.
- [ ] `just test` succeeds.
- [ ] `just test-integration` succeeds in an environment with Postgres and
  Redis.
- [ ] `just test-e2e` covers at least one full browser-style auth flow.

## Stage 17: Final hardening

- [ ] Threat-model public auth endpoints:
  - [ ] Login.
  - [ ] Registration.
  - [ ] Password reset.
  - [ ] OIDC callback.
  - [ ] WebAuthn challenge and assertion.
  - [ ] OAuth authorize and token.
- [ ] Review anti-enumeration behavior across every public endpoint.
- [ ] Review timing behavior for login and reset.
- [ ] Review secret handling:
  - [ ] No raw secrets in logs.
  - [ ] No raw tokens in audit events.
  - [ ] No credential payloads in error messages.
  - [ ] No secret refs resolved after startup except through the configured
    provider.
- [ ] Review cryptography:
  - [ ] Argon2 parameters match config.
  - [ ] AES-GCM nonces are unique.
  - [ ] PASETO keys rotate and old keys remain for the overlap window.
  - [ ] Recovery code randomness is unbiased.
- [ ] Review OAuth2 compliance:
  - [ ] No implicit grant.
  - [ ] No resource owner password credentials grant.
  - [ ] PKCE required for public clients.
  - [ ] Redirect URI exact match.
  - [ ] Audience restriction enforced.
- [ ] Prepare a security review checklist for future PRs.

Exit criteria:

- [ ] Security-sensitive behaviors are documented in `docs/ARCHITECTURE.md`.
- [ ] Implementation details and commands are documented in
  `docs/IMPLEMENTATION.md`.
- [ ] The project has a clear demo path showing password, MFA, passkey, OIDC,
  OAuth2, and organization flows.
