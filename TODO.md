# Aether Auth TODO

This TODO is ordered by dependency, not by feature appeal. The first stages
define the contracts, storage, and security invariants that every auth method
needs. Zitadel reuse starts only after those contracts exist, so copied or
ported code can fit Aether's Gin, sqlc, PASETO, and feature-module structure.

When copying code from Zitadel, keep AGPL-3.0-only compatibility, attribution,
SPDX headers when present, and a short note in the destination package naming
the source file. Prefer small ports over importing Zitadel's command/query and
eventstore architecture.

## Future Hurl HTTP integration plan

Use Go integration tests for repository, transaction, sqlc, Redis, and worker
internals. Use Hurl for black-box HTTP flows once a stage exposes real routes
and can run against a migrated local stack. Hurl tests belong with the e2e
layer, not the fast `just test` unit gate.

- [x] Add a Hurl harness when the first black-box account route is ready:
  - [x] Create `test/e2e/hurl/` with a short README, environment example, and
    staged flow files such as `stage04-registration.hurl`.
  - [x] Add a `just test-hurl` target that runs Hurl against a caller-provided
    `BASE_URL`, defaulting to the local API port.
  - [x] Document the required startup order: podman stack, migrations, API,
    worker when async mail or cleanup behavior is under test.
  - [x] Keep generated account names, emails, passwords, reset tokens, OAuth
    codes, and session tokens out of source-controlled fixtures.
- [ ] Stage 4 Hurl flow: account registration and credential API smoke tests.
  - [x] Register a valid account after the registration route is mounted.
  - [x] Assert the response shape never includes password hashes, encrypted
    credential payloads, reset tokens, or other secret material.
  - [x] Repeat registration with the same username and email and assert the
    public anti-enumeration contract.
  - [ ] Exercise credential listing/removal only after Stage 6 can provide an
    authenticated session for protected account settings routes.
- [ ] Stage 5 Hurl flow: password login public contract.
  - [ ] Login with a registered account and assert the common session result
    shape.
  - [ ] Compare wrong username, wrong password, inactive account, and lockout
    responses for the same public error contract.
  - [ ] Drive enough failures to prove rate limiting or lockout surfaces as the
    documented public response.
- [ ] Stage 6 Hurl flow: session lifecycle.
  - [ ] Login, call an authenticated account endpoint, refresh, and logout.
  - [ ] Attempt refresh-token reuse and assert the session family is revoked.
  - [ ] Verify a partial-session token cannot authorize normal account APIs.
- [ ] Stage 7 Hurl flow: password plus TOTP and recovery-code login.
  - [ ] Enroll and confirm TOTP, then prove password login returns a partial
    session until the TOTP factor is verified.
  - [ ] Use one recovery code successfully and assert replay fails.
  - [ ] Assert raw TOTP codes and recovery codes never appear in responses.
- [ ] Stage 8 Hurl flow: WebAuthn HTTP contract.
  - [ ] Keep successful registration/assertion coverage in Go e2e tests with
    the adapted virtual WebAuthn client.
  - [ ] Use Hurl for challenge response shape, malformed payloads, expired
    challenge, and replay rejection once those routes exist.
- [ ] Stage 9 Hurl flow: external OIDC callback behavior.
  - [ ] Run authorize and callback paths against a local mock provider.
  - [ ] Assert redirect, state, nonce, PKCE, provider-error, and auto-create
    disabled responses.
- [ ] Stage 10 Hurl flow: password reset.
  - [x] Submit reset requests for known and unknown accounts and assert public
    response parity.
  - [ ] Read the captured reset email from the local mail test service, confirm
    the reset, then assert token replay fails.
  - [ ] Confirm old sessions stop working after reset.
- [ ] Stage 11 Hurl flow: OAuth2 authorization server.
  - [ ] Exercise authorization-code plus PKCE, token exchange, refresh
    rotation, and consent revoke.
  - [ ] Assert exact redirect URI matching, scope downscoping, and invalid
    client behavior through public HTTP responses.
- [ ] Stage 12 Hurl flow: organization invitation and RBAC.
  - [ ] Create an organization, invite a user, accept the invitation, and assert
    membership claims or account-visible membership state.
  - [ ] Exercise cross-organization access rejection and last-owner protection
    through public APIs.
- [ ] Stage 13 Hurl flow: audit-backed account activity.
  - [ ] Trigger login, reset, session revoke, OAuth, and organization events
    through HTTP.
  - [ ] Assert any account-facing recent-activity endpoint shows expected event
    summaries without raw secrets.
- [ ] Stage 14 Hurl flow: browser-facing security controls.
  - [ ] Assert secure headers on rendered login, MFA, reset, consent, sessions,
    and authorized-apps pages.
  - [ ] Assert CSRF failures for mutating browser-style requests and `403`
    responses for insufficient scopes.
- [ ] Stage 15 Hurl flow: async side effects visible through HTTP.
  - [ ] Trigger reset and invitation email flows and assert captured mail is
    produced without sending real email.
  - [ ] Exercise cleanup-visible behavior, such as expired reset tokens or OAuth
    codes no longer working after worker cleanup runs.
- [ ] Stage 16 Hurl gate: include the stable Hurl flows in an optional CI job
  that runs after the containerized stack and migrations are ready.
- [ ] Stage 17 Hurl hardening suite: keep anti-enumeration, timing-tolerant
  response-shape checks, redirect validation, and secret-leak regression tests
  available for security review.

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
- [x] Define cross-feature interfaces with small method sets:
  - [x] `AccountRepository` for account lookup and state checks.
  - [x] `CredentialRepository` for credential lookup, create, update, and
    last-credential safety checks.
  - [x] `ChallengeStore` for WebAuthn, OIDC state, nonce, PKCE, and one-time
    challenge TTLs.
  - [x] `FactorStore` for partial-session factor state.
  - [x] `SessionIssuer` for partial and full session creation.
  - [x] `AuditWriter` for security events.
  - [x] `RateLimiter` for IP, account, and endpoint limits.
  - [x] `Clock`, `RandomReader`, and `IDGenerator` for deterministic tests.
  - [x] `PasswordHasher`, `PasswordPolicy`, and `BreachChecker`.
  - [x] `SecretBox` or `Encryptor` for AES-256-GCM encrypted credential data.
- [x] Define typed service errors before handlers exist:
  - [x] Internal error kinds for invalid credentials, locked account, expired
    challenge, replayed challenge, malformed input, provider failure,
    insufficient scope, and policy denial.
  - [x] Public error mapping with generic login and reset responses.
  - [x] `application/problem+json` helpers in `internal/platform/httpx`.
  - [x] A stable place for error IDs if Zitadel's `internal/zerrors` model is
    adapted.
- [x] Define module wiring conventions:
  - [x] Every feature exposes `Module`, `Deps`, `New(deps)`, and
    `RegisterRoutes`.
  - [x] `internal/httpapi/router.go` remains the only complete URL map.
  - [x] No feature package reads global config or opens its own DB, Redis,
    mailer, queue, or logger.
- [x] Add unit tests for interface-level behavior:
  - [x] Fake `AuthMethod` implementations can be registered and called by the
    orchestrator.
  - [x] Public error mapping never leaks account existence.
  - [x] Clock and random fakes make challenge expiry tests deterministic.

Exit criteria:

- [x] A skeleton auth orchestrator can register at least two fake methods.
- [x] `just test` passes without external services.
- [x] New interfaces are documented enough that password and WebAuthn can be
  implemented without changing their shape.

## Stage 2: Persistence foundation

This stage gives every later feature stable storage. Translate Zitadel schema
ideas into Aether migrations and sqlc queries; do not copy Zitadel's dynamic
repository layer.

- [x] Add initial migrations in dependency order:
  - [x] Accounts, emails, credentials.
  - [x] Credential encrypted payload metadata.
  - [x] Login attempts and lockout state.
  - [x] Sessions, refresh tokens, partial sessions, and session factors.
  - [x] WebAuthn challenges and credentials if not stored in generic
    credential payloads.
  - [x] OIDC provider links and pending OIDC states.
  - [x] TOTP credentials and recovery-code hashes.
  - [x] Password reset tokens.
  - [x] OAuth clients, authorization codes, consent grants, and OAuth refresh
    tokens.
  - [x] Organizations, memberships, and invitations.
  - [x] Audit log.
- [x] Use Zitadel schema references for shape and indexes:
  - [x] `backend/v3/storage/database/dialect/postgres/migration/011_session_table/up.sql`.
  - [x] `backend/v3/storage/database/dialect/postgres/migration/013_user_table/up.sql`.
  - [x] `backend/v3/storage/database/dialect/postgres/migration/017_archived_sessions_table/up.sql`.
- [x] Add sqlc query files under `db/queries/`:
  - [x] Account lookup by username, email, ID.
  - [x] Credential lookup by account, kind, provider, credential ID, and
    external subject.
  - [x] Challenge insert, consume, expire, and delete.
  - [x] Login attempt update and lockout calculation.
  - [x] Session create, list, revoke, rotate refresh token, and revoke chain.
  - [x] Audit append and recent login query.
- [x] Regenerate sqlc output with `just sqlc`.
- [x] Add repository wrappers that depend on `sqlc.Queries`, not raw SQL in
  handlers.
- [x] Add integration tests behind `//go:build integration` for migrations and
  repository behavior.

Exit criteria:

- [x] `just sqlc` succeeds.
- [x] `just test` still avoids integration tests.
- [x] `just test-integration` covers the first repository batch when Postgres
  is available.

## Stage 3: Platform primitives

- [x] Finish `internal/platform/crypto`:
  - [x] Argon2id PHC-string encode, parse, verify, and needs-rehash helpers.
  - [x] HMAC-SHA-256 pepper pre-hash for passwords.
  - [x] AES-256-GCM seal/open helpers for credential payloads.
  - [x] CSPRNG helpers with unbiased random string generation.
  - [x] Constant-time comparison helpers where needed.
- [x] Finish `internal/platform/paseto`:
  - [x] Load Ed25519 signing keys from secret refs.
  - [x] Load v4.local symmetric keys from secret refs.
  - [x] Issue and verify v4.public access tokens.
  - [x] Issue and verify v4.local partial-session tokens.
  - [x] Support `kid` footers and implicit assertions.
- [x] Finish `internal/platform/keys`:
  - [x] Public key endpoint format for `/.well-known/paseto-keys`.
  - [x] Key rotation schedule and overlap window.
  - [x] Worker task or cron registration for rotation.
- [x] Finish `internal/platform/httpx`:
  - [x] Problem response helpers.
  - [x] Generic auth failure helpers.
  - [x] Timing equalizer helper for login and reset flows.
- [x] Finish `internal/ratelimit`:
  - [x] Redis-backed IP, account, and endpoint buckets.
  - [x] Middleware hooks usable before auth verification.
  - [x] Unit tests with fake limiter and integration tests with Redis.
- [x] Add test helpers under `internal/testutil`:
  - [x] Fake clock.
  - [x] Deterministic random reader.
  - [x] JSON assertion helper for Gin handlers.
  - [x] Config builder with safe defaults.
  - [x] Repository integration harness.

Exit criteria:

- [x] Crypto helpers have table-driven tests and invalid-input tests.
- [x] PASETO keystore is no longer a stub.
- [x] The public key endpoint returns active verification keys.

## Stage 4: Account and credential core

- [x] Implement account registration service:
  - [x] Username normalization and validation.
  - [x] Email normalization, uniqueness, and optional verification state.
  - [x] Anti-enumeration behavior when username or email is already taken.
  - [x] Audit events for registration attempts.
- [x] Implement credential management:
  - [x] Generic credential create, read, update, delete.
  - [x] Encrypted credential payload serialization.
  - [x] Provider-specific uniqueness for OIDC credentials.
  - [x] Last-credential removal protection.
  - [x] Re-authentication requirement for destructive credential changes.
- [x] Add account settings routes:
  - [x] Read profile.
  - [x] Update display name or profile metadata.
  - [x] List credentials without exposing secrets.
  - [x] Remove credential when policy allows it.
- [x] Add repository and handler tests:
  - [x] Duplicate username and duplicate email behavior.
  - [x] Last credential cannot be removed.
  - [x] Public responses do not reveal whether an account exists.

Exit criteria:

- [x] Accounts and credentials can be created without sessions.
- [x] Credential payloads are encrypted at rest.
- [x] Account APIs are mounted through `internal/httpapi/router.go`.

## Stage 5: Auth orchestrator and password auth

This is the first real `AuthMethod` implementation. Use Zitadel's password
state-transition tests as references, but keep Aether's NIST/OWASP password
policy.

- [x] Implement `internal/auth` orchestrator:
  - [x] Register `AuthMethod` implementations by `CredentialKind`.
  - [x] Enforce rate limiting before credential verification.
  - [x] Normalize public login errors to `invalid_credentials`.
  - [x] Run dummy password work for missing accounts.
  - [x] Apply timing equalization on success, failure, and lockout paths.
  - [x] Emit audit events for success and failure.
- [x] Implement `internal/auth/password`:
  - [x] Password set/change with policy checks.
  - [x] HIBP k-anonymity breach check with Redis cache.
  - [x] Argon2id hash with pepper.
  - [x] Password verification outside DB transactions.
  - [x] Rehash on login when parameters change.
- [x] Reuse or port from Zitadel:
  - [x] `backend/v3/domain/session_check_password.go` for the factor update
    model.
  - [x] `internal/command/user_human_password.go` for transaction boundaries
    and lockout flow.
  - [x] `internal/command/user_human_password_test.go` for failure and lockout
    cases.
- [x] Keep Aether-specific behavior:
  - [x] No copied password composition rules.
  - [x] Generic public errors for wrong username, wrong password, inactive
    account, and lockout.
  - [x] Forgot-password remains available during lockout.
- [x] Add route tests for `POST /auth/login` with password credentials.

Exit criteria:

- [x] Password login can issue either a full session or a partial MFA session.
- [x] Failed attempts update lockout state in one transaction.
- [x] Login tests cover wrong username, wrong password, locked account, and
  valid login without distinguishable public errors.

## Stage 6: Session lifecycle and token issuance

- [x] Implement full session creation:
  - [x] Generate persisted UUIDv7 session IDs and 256-bit token identifiers.
  - [x] Store only a SHA-256 hash of opaque refresh tokens.
  - [x] Persist IP, user agent, expiry, and auth factors.
  - [x] Issue PASETO v4.public access tokens.
  - [x] Issue opaque refresh tokens stored as hashes.
- [x] Implement partial sessions:
  - [x] v4.local token with two-minute TTL.
  - [x] Claims limited to MFA verification.
  - [x] Factor state bound to account and challenge context.
- [x] Implement refresh rotation:
  - [x] Rotate refresh token on every use.
  - [x] Detect reused refresh tokens.
  - [x] Revoke the whole rotation chain on reuse.
- [x] Implement session revocation:
  - [x] User-initiated session deletion.
  - [x] Password-change revocation.
  - [x] Admin revocation hook for later organization work.
  - [x] Redis revocation set keyed by access-token `jti`.
- [x] Add account session APIs:
  - [x] `GET /account/sessions`.
  - [x] `DELETE /account/sessions/{id}`.
- [x] Add tests:
  - [x] Access token claims and footers.
  - [x] Refresh rotation and reuse detection.
  - [x] Revocation cache TTL.
  - [x] Partial token cannot authorize normal APIs.
  - [x] Account session list and revocation APIs.

Exit criteria:

- [x] Password login can produce usable access and refresh tokens.
- [x] Refresh token reuse terminates the session family.
- [x] Revoked access-token IDs are rejected by middleware.

## Stage 7: MFA factor model, TOTP, and recovery codes

This stage should start after sessions exist, because MFA uses partial session
tokens and factor state.

- [x] Implement shared MFA policy:
  - [x] Account-level `mfa_enforced`.
  - [x] Organization-level `mfa_required` hook for later org stage.
  - [x] Required factors derived from account and org policy.
  - [x] Upgrade from partial session to full session only after required
    factors are verified.
- [x] Reuse or port Zitadel's session factor model:
  - [x] `backend/v3/domain/session_factor.go`.
  - [x] `backend/v3/domain/session_check_user.go`.
  - [x] `backend/v3/domain/session_check_totp.go`.
  - [x] `backend/v3/domain/session_check_recovery_code.go`.
- [x] Implement `internal/auth/totp`:
  - [x] TOTP enrollment with QR provisioning URI.
  - [x] Secret encryption with AES-256-GCM.
  - [x] RFC 6238 verification with one-window tolerance.
  - [x] Recovery-code generation using unbiased CSPRNG selection.
  - [x] Recovery-code hashing and single-use consume.
  - [x] Lockout behavior for repeated MFA failures.
- [x] Reuse or port Zitadel helpers:
  - [x] `internal/domain/human_otp.go`.
  - [x] `internal/domain/human_recovery_codes.go`.
  - [x] `internal/command/user_human_otp.go`.
  - [x] `internal/command/user_human_recovery_codes.go`.
- [x] Do not copy:
  - [x] Zitadel AES-CFB helpers for encrypted-at-rest data.
  - [x] Biased random string generation for recovery codes.
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

- [x] Implement reset request:
  - [x] Accept username or email.
  - [x] Always return the same public message.
  - [x] Apply rate limiting before lookup.
  - [x] Generate a 256-bit random token.
  - [x] Store only SHA-256 token hash.
  - [x] Use fixed or allowlisted reset URL origin.
  - [x] Queue reset email through Asynq.
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
  - [x] Unknown account response parity.
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
