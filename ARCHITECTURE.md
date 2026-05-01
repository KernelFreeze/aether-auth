# Architecture

Aether Auth is a self-hosted identity and authorization service written in Go.
It owns account identity, credential verification, MFA, sessions, organization
membership, OAuth2 consent, and scoped token issuance.

This document describes the service contract and the security decisions behind
it. Package layout, library choices, boot wiring, and local workflows are covered
in `docs/IMPLEMENTATION.md`.

## Status

The repository is still in the scaffold phase. The package boundaries,
migrations, sqlc query files, and core interfaces are present, but several
feature implementations are intentionally skeletal. The architecture below is
the target contract those packages are being built toward.

## Design principles

1. **No implicit trust.** First-party and third-party clients use the same
   OAuth2 model. Every client asks for explicit scopes and receives tokens for a
   specific audience.
2. **Credentials are pluggable.** Passwords, passkeys, external OIDC identities,
   and TOTP factors are records attached to an account. Email is a contact
   method, not the account identifier.
3. **Security behavior is part of the API.** Generic auth errors, uniform
   response timing, pre-verification rate limits, refresh-token rotation,
   explicit revocation, and audit events are required behavior, not optional
   hardening.

## System shape

The service has three executables:

- `cmd/api` runs the Gin HTTP API.
- `cmd/worker` runs background tasks such as email delivery, cleanup, audit
  shipping, and key rotation.
- `cmd/migrate` applies database migrations explicitly.

The API and worker do not auto-migrate at boot. Schema changes are applied
through the migration binary or `just migrate-*` recipes so deploys stay
predictable.

Durable state lives in PostgreSQL. Redis is used for short-lived state: rate
limits, challenge state, revocation sets, HIBP cache entries, and Asynq queues.
Runtime configuration is environment-driven, with secrets resolved through URI
references such as `env://AUTH_PEPPER`.

## Bounded contexts

The codebase is feature-oriented. Each feature package owns its handlers,
service logic, repository code, module wiring, and tests. Shared infrastructure
lives under `internal/platform`.

```text
cmd/
  api/             HTTP listener
  worker/          background task processor
  migrate/         migration CLI wrapper
internal/
  account/         accounts, credentials, emails, registration
  auth/            login orchestration and credential verifiers
  session/         PASETO issuance, refresh rotation, revocation
  mfa/             MFA policy and partial sessions
  passwordreset/   reset request and confirmation flows
  oauth/           OAuth2 authorization server
  org/             organizations, invitations, RBAC
  audit/           security event log
  ratelimit/       Redis-backed rate limiting
  httpapi/         Gin router and middleware wiring
  platform/        config, db, Redis, queue, mailer, PASETO, secrets
  workers/         Asynq task handlers
db/queries/        sqlc query files
migrations/        numbered up/down SQL migrations
templates/         auth pages and email templates
test/e2e/          end-to-end HTTP flows
```

`internal/httpapi/router.go` owns the URL map. Feature modules register routes
through a small `Module` contract and receive typed dependencies instead of
reading globals.

## Identity model

An account has an opaque UUID primary key, a case-insensitive username, profile
metadata, and policy state such as lockout or MFA requirements. Usernames are
public identifiers. Emails are separate contact records and may be added,
removed, verified, or made primary without changing the account identity.

Credentials are separate records linked to an account. The credential `kind`
decides how verification works:

- `password` stores an Argon2id password hash.
- `webauthn` stores passkey credential data and the public key.
- `oidc` stores an external provider and subject claim.
- `totp` stores an encrypted TOTP secret for MFA.

An account can hold multiple credential types at the same time. Removing or
changing sensitive credentials requires recent authentication.

## Authentication

`POST /auth/login` is the shared entry point for credential verification. The
auth orchestrator routes by credential kind and enforces the same public
contract for every method:

- Rate limits run before credential verification.
- Failed login responses use the same public error shape.
- Missing accounts, wrong credentials, locked accounts, and other failures do
  not expose distinguishable timing.
- Security-relevant outcomes are written to the audit log.

Password login uses Argon2id with a server-side pepper. Password rules follow
OWASP and NIST guidance: minimum length, maximum length, Unicode support, no
composition rules, no forced rotation, and breach checks when passwords are set
or changed.

Passkey login follows the WebAuthn relying-party flow. Challenges are random,
single-use, bound to the initiating session, and short-lived.

External login uses OAuth2 authorization code with PKCE against configured OIDC
providers. Redirect URIs are exact-match allowlisted. The `state`, nonce, and
PKCE verifier are bound to server-side challenge state before the callback is
accepted.

## Multi-factor authentication

MFA is modeled as additional factor state on the account. After primary
authentication, the service decides whether the user can receive a full session
or must complete another factor.

When MFA is required, the service issues a short-lived partial session using
PASETO `v4.local`. That token can only call the MFA verification endpoint. Once
the required factors are satisfied, the service issues the normal session.

Supported MFA paths are TOTP, a WebAuthn credential registered as a second
factor, and single-use recovery codes. TOTP secrets and credential blobs are
encrypted at rest. Recovery codes are generated from a cryptographic random
source and stored as hashes.

## Sessions and tokens

A successful login creates a server-side session and returns two client tokens:

- **Access token:** PASETO `v4.public`, signed with Ed25519, short-lived, and
  intended for resource servers to verify without calling Aether Auth on every
  request.
- **Refresh token:** opaque random value, stored server-side as a hash, scoped
  to the token endpoint, and rotated on every use.

Refresh-token reuse is treated as theft. If a rotated token is presented again,
the rotation chain is revoked and the session is terminated.

Access tokens carry claims such as subject, issuer, audience, expiry, scopes,
organization context, and `jti`. The PASETO footer carries the key ID used for
verification. Resource servers fetch public keys from
`/.well-known/paseto-keys` and cache them through the rotation overlap window.

Browser cookies use `Secure`, `HttpOnly` where appropriate, `SameSite=Lax` or
`SameSite=Strict`, scoped paths, and no explicit `Domain`.

## OAuth2 authorization server

Aether Auth is also an OAuth2 authorization server. Every application is a
registered client with a client type, allowed scopes, redirect URIs, and consent
rules.

Interactive clients use authorization code with PKCE. The implicit grant and
resource owner password credentials grant are not implemented. Authorization
codes are random, single-use, short-lived, and bound to the client, redirect
URI, code challenge, account, and approved scope.

Machine-to-machine clients use client credentials. Tokens issued through this
grant use a service subject and only the service scopes granted to that client.
For high-trust service calls, sender-constrained tokens with mTLS are preferred.

Every access token has a single audience. If a client needs to call multiple
resource servers, it receives separate audience-specific tokens or uses token
exchange to downscope.

Consent grants are persisted and user-reviewable. Revoking consent invalidates
refresh tokens for that account-client pair and revokes active access tokens
where possible.

## Organizations and authorization

Accounts can belong to multiple organizations. Membership roles are
hierarchical:

- `owner` has full control, including ownership transfer and deletion.
- `admin` manages members and organization settings.
- `member` has non-administrative access.

At least one owner must remain on every organization.

Invitations are scoped to an email address, role, organization, inviter, and
expiry. The invitation token is stored only as a hash.

Resource servers enforce authorization in middleware before a handler runs:

1. Verify the PASETO signature.
2. Check issuer, audience, expiry, and revocation state.
3. Check the endpoint's required scope.
4. Check that the requested resource belongs to the token's organization.
5. Check that the membership role is high enough for the action.

## Anti-enumeration and abuse controls

Public identity endpoints must not reveal whether an account, username, email,
or external identity exists. Login, registration, password reset, and OIDC
callback paths use generic responses and equalized work where needed.

Rate limits are applied per IP, per account or username, and per endpoint.
Progressive lockout protects targeted accounts after repeated failures.
Password reset remains available during lockout to avoid turning lockout into a
denial-of-service tool.

CAPTCHA may be used after repeated failures, but it is only a secondary control.
The primary controls are rate limiting, lockout, generic responses, audit
events, and session revocation.

## Password reset and recovery

Password reset follows the same anti-enumeration rules as login. The request
endpoint always returns the same public response. If the account exists, the
service creates a short-lived random token, stores only its hash, and sends the
plaintext token by email.

Reset links are built from configured trusted domains, never from the incoming
`Host` header. Reset pages use `Referrer-Policy: no-referrer` to avoid leaking
tokens through browser navigation.

Confirming a reset validates the token, checks the new password, stores the new
Argon2id hash, marks the token as used, and revokes existing sessions.

## Browser security

Browser-backed flows use CSRF protection in addition to SameSite cookies.
Server-rendered forms use synchronizer tokens. SPA-style clients may use a
cookie-to-header token pattern where the server verifies that the custom header
matches the CSRF cookie.

The service UI escapes user-controlled values by context and sends defensive
headers, including Content Security Policy, HSTS,
`X-Content-Type-Options: nosniff`, and frame protections.

Pure bearer-token API clients do not need CSRF protection because browsers do
not attach bearer tokens automatically.

## Audit log

Security-relevant events are written to an append-only audit log:

- login success and failure
- MFA challenge and verification results
- password changes and resets
- session creation and revocation
- OAuth authorization and consent revocation
- organization invitations and membership changes

Failed login events store a hash of the attempted username instead of the raw
value. The audit log supports user-visible recent activity and can feed anomaly
detection for step-up authentication.

## Cryptography

| Concern | Mechanism |
|---|---|
| Password hashing | Argon2id plus server-side HMAC pepper |
| Access tokens | PASETO `v4.public` with Ed25519 signatures |
| Partial and internal tokens | PASETO `v4.local` with XChaCha20 and BLAKE2b |
| Refresh tokens and reset tokens | Opaque random values, stored as hashes |
| TOTP secrets and credential blobs | AES-256-GCM with keys from the secrets provider |
| Transport | HTTPS-only with HSTS |
| Database access | Parameterized SQL through sqlc-generated code |

Signing keys rotate on a schedule. Old public keys remain available until all
tokens signed by them have expired. Symmetric keys are resolved from the secrets
provider and rotated independently.

## API surface

```text
POST   /auth/register
POST   /auth/login
POST   /auth/mfa/verify
POST   /auth/reset-password/request
POST   /auth/reset-password/confirm

GET    /auth/webauthn/challenge
POST   /auth/webauthn/register
GET    /auth/oidc/{provider}/authorize
GET    /auth/oidc/{provider}/callback

GET    /oauth/authorize
POST   /oauth/token
POST   /oauth/revoke

GET    /account/sessions
DELETE /account/sessions/{id}
GET    /account/authorized-apps
DELETE /account/authorized-apps/{client_id}

POST   /orgs
POST   /orgs/{slug}/invitations
POST   /orgs/{slug}/invitations/{token}
DELETE /orgs/{slug}/members/{account_id}
PATCH  /orgs/{slug}/members/{account_id}

GET    /.well-known/paseto-keys
```

## Documentation boundaries

Update this file when the auth, token, session, OAuth, MFA, organization, audit,
or browser-security contract changes. Update `docs/IMPLEMENTATION.md` when the
package layout, boot sequence, commands, testing strategy, or dependency choices
change.
