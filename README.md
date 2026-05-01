# Aether Auth

Aether Auth is a self-hosted identity and authorization service for Go systems that need more than a login endpoint. It handles account identity, credential verification, MFA, session management, organization membership, OAuth2 consent, and scoped token issuance from one service.

The service is built around three ideas:

- Every client, including first-party services, authenticates through OAuth2 and receives only the scopes it requested and was allowed to use.
- Accounts are identified by usernames, not email addresses. Email is a contact method, and an account can have multiple credentials attached to it.
- Security behavior is part of the product contract: generic auth errors, uniform response timing, rate limiting before credential checks, explicit session revocation, and auditable security events.

## What it provides

Aether Auth is both an identity provider and an OAuth2 authorization server.

It supports password login with Argon2id, passkeys through WebAuthn, external OIDC login with providers such as Google or GitHub, TOTP, recovery codes, password reset, and multi-factor step-up. Credentials are stored as separate records on an account, so a user can keep a password, a passkey, and a social login linked to the same identity.

Sessions use short-lived PASETO v4.public access tokens and opaque rotating refresh tokens. Partial sessions use PASETO v4.local while a user completes MFA. Resource servers verify issuer, audience, expiry, revocation, organization context, and scopes before a request reaches application code.

OAuth2 support includes authorization code with PKCE, refresh token rotation, client credentials for service-to-service access, exact-match redirect URI validation, user consent, consent revocation, and audience-restricted access tokens. The implicit and password grants are intentionally absent.

Organizations are first-class. Accounts can belong to multiple organizations, roles are hierarchical (`owner`, `admin`, `member`), and invitations are scoped to an email address and role. Tokens can carry organization context so downstream services can enforce tenant boundaries.

## Security model

Aether Auth follows the OWASP guidance for authentication, session management, password storage, OAuth2, CSRF, and credential-stuffing prevention.

Password storage uses Argon2id with a server-side pepper. Password policy follows NIST-style rules: length limits, Unicode support, no composition rules, and breach checks through the Have I Been Pwned k-anonymity API.

Public auth endpoints avoid user enumeration. Login, registration, and password reset return generic responses and equalize timing across success, failure, missing-account, and locked-account paths. Rate limits run per IP, per account, and per endpoint before expensive credential verification.

Security-relevant events are written to an append-only audit log: login success and failure, MFA checks, password changes, password reset, session revocation, OAuth authorization, consent revocation, and organization membership changes. Failed login events store a hash of the attempted username instead of the plaintext value.

Browser flows use CSRF tokens and secure cookie settings. Refresh tokens are scoped to the token endpoint, marked `HttpOnly` and `Secure`, and rotated on every use. PASETO signing keys rotate on a schedule, with old public keys kept through an overlap window for verification.

## Architecture

The codebase is feature-oriented. Each bounded context owns its handlers, service logic, repository code, module wiring, and tests. Cross-cutting infrastructure lives under `internal/platform`.

```text
cmd/
  api/           HTTP listener
  worker/        background task processor
  migrate/       migration CLI wrapper
internal/
  account/       accounts, credentials, emails, registration
  auth/          login orchestration and credential verifiers
  session/       PASETO tokens, refresh rotation, revocation
  mfa/           MFA policy and partial sessions
  passwordreset/ password reset flows
  oauth/         OAuth2 authorization server
  org/           organizations, invitations, RBAC
  audit/         security event log
  ratelimit/     Redis-backed rate limiting
  httpapi/       Gin router and middleware wiring
  platform/      config, db, Redis, queue, mailer, PASETO, secrets
  workers/       Asynq task handlers
db/queries/      sqlc query files
migrations/      numbered up/down SQL migrations
templates/       server-rendered auth pages and email templates
test/e2e/        end-to-end HTTP flows
```

The main API process does not run migrations at boot. Schema changes are applied explicitly through `cmd/migrate` or the `just migrate-*` recipes, which keeps deploys predictable.

## Technology stack

- Go and Gin for the HTTP API.
- PostgreSQL with pgx and sqlc for persistence.
- Redis for rate limits, token revocation, HIBP caching, and Asynq queues.
- PASETO v4 for access, partial-session, and internal tokens.
- Argon2id, Ed25519, XChaCha20, and AES-256-GCM for the core cryptographic paths.
- Fosite for OAuth2 server behavior.
- `go-webauthn/webauthn` for passkeys.
- `go-oidc` and `oauth2` for external OIDC login.
- Mailpit in local development so email flows can be tested without sending real mail.
- Podman for the local service stack and container builds.

## Getting started

Install Go, `just`, Podman, and the database tooling you use locally. The containerized development stack starts PostgreSQL, Redis, and Mailpit.

```bash
git clone git@github.com:KernelFreeze/aether-auth.git
cd aether-auth
cp .env.example .env
podman compose -f podman-compose.yml up -d postgres redis mailpit
just migrate-up
just run
```

In another terminal, start the worker:

```bash
just worker
```

The API listens on `http://localhost:8080` by default. Mailpit is available at `http://localhost:8025`.

## Configuration

Runtime configuration is environment-driven. `.env.example` contains local defaults, and `configs/config.example.yaml` documents the same settings in grouped form for operators.

Secrets are referenced by URI instead of being embedded directly in the structured config. For example, `SECRET_PEPPER_REF=env://AUTH_PEPPER` tells the secrets provider to resolve the password pepper from the `AUTH_PEPPER` environment variable. The `env://` provider is available by default, and the interface is designed for Vault or cloud secret managers.

Important configuration groups include server settings, PostgreSQL, Redis, queue, mailer, issuer metadata, Argon2id parameters, session TTLs, PASETO rotation windows, OAuth2 defaults, rate limits, lockout policy, CSRF, CORS, audit sink, logging, and organization defaults.

## Development commands

Use `just` as the project task runner.

```bash
just build             # build bin/api, bin/worker, and bin/migrate
just run               # run the API, using air when installed
just worker            # run the background worker
just test              # run unit tests
just test-integration  # run tests tagged with integration
just test-e2e          # run end-to-end tests
just fmt               # format Go code
just vet               # run go vet
just lint              # run golangci-lint
just podman-build      # build the application image
just podman-run        # start the containerized stack
just sqlc              # regenerate sqlc code
just gen-mocks         # regenerate moq mocks
```

Migration helpers:

```bash
just migrate-up
just migrate-down n=1
just migrate-new slug=add_audit_indexes
just migrate-version
```

## Testing

Unit tests live beside the package under test and must not require PostgreSQL, Redis, SMTP, Podman, network access, or real secrets. Use fakes for collaborators such as repositories, token issuers, queue clients, mailers, audit writers, rate limiters, clocks, random readers, and password hashers. Shared helpers belong in `internal/testutil`.

Integration tests cover code that needs real PostgreSQL, Redis, migrations, or generated sqlc queries. They live beside the package under test as `integration_test.go` files and use the `integration` build tag.

End-to-end tests live under `test/e2e` with the `e2e` build tag and exercise complete HTTP flows against the containerized stack.

## API overview

The main public surfaces are:

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

See `docs/ARCHITECTURE.md` for the security model and API behavior, `docs/IMPLEMENTATION.md` for package wiring and development conventions, and `docs/ZITADEL_REUSE.md` for notes on porting selected implementation ideas from Zitadel.

## License

Aether Auth is licensed under AGPL-3.0-only. See `LICENSE` and `LICENSING.md`.
