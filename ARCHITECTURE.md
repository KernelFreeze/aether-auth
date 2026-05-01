# Architecture

Aether Auth is a self-hosted identity and authorization provider — comparable in scope to Auth0 or Clerk — written in Go. This document captures the fundamental architectural decisions that shape the system. Implementation-level detail lives elsewhere.

## Guiding principles

1. **No implicit trust.** First-party and third-party applications authenticate through the same OAuth2 flows. No service receives unscoped access to identity data.
2. **Credentials are pluggable.** Passwords, passkeys, social logins, and TOTP are interchangeable records attached to an account. The account itself is identified by an opaque UUID and a username — never by an email address.
3. **OWASP compliance by default.** The OWASP Top Ten and Cheat Sheet Series inform every subsystem.

## Stack

- **Language:** Go, with Gin for HTTP routing.
- **Persistence:** PostgreSQL for durable state; Redis for ephemeral state (rate limiting, revocation sets, single-use challenges).
- **Tokens:** PASETO v4 — `v4.public` (Ed25519) for access tokens, `v4.local` (XChaCha20 + BLAKE2b) for partial-session and internal tokens.

PASETO is chosen over JWT to eliminate the algorithm-confusion class of vulnerabilities. The algorithm is fixed per version, with no `alg` header and no `none` mode.

## Identity model

- **Account** — opaque UUID primary key, case-insensitive username, optional display name. Emails are contact methods, not identifiers.
- **Credential** — a row keyed by `kind` (`password`, `webauthn`, `oidc`, `totp`). An account can hold any combination simultaneously.
- **Email** — independent records, multiple per account, each with its own verification state.

## Authentication

A single login orchestrator (`POST /auth/login`) routes by credential `kind` and enforces three invariants on every path:

- **Uniform response timing** to prevent user enumeration (dummy Argon2id work on cache miss).
- **Generic errors** — always `401 invalid_credentials`, regardless of the underlying reason.
- **Rate limiting before verification**, applied per-IP and per-username.

Passwords are hashed with Argon2id and a server-side pepper. Passkeys use the WebAuthn relying-party protocol. Social logins use OAuth2 authorization code with PKCE; redirect URIs are exact-match allowlisted.

## Multi-factor authentication

MFA is modeled as a second credential. After primary auth, the orchestrator may issue a short-lived **partial session** token whose only permitted use is the MFA verification endpoint. Supported factors are TOTP and a second WebAuthn credential, with single-use recovery codes as backup.

## Sessions

- **Access token:** PASETO `v4.public`, short-lived (~15 min), verified by resource servers using a published Ed25519 key.
- **Refresh token:** opaque, server-side (hashed), sliding window with absolute expiry, rotated on every use. Reuse of a rotated refresh token revokes the entire chain.
- **Cookies:** `Secure`, `HttpOnly` where applicable, `SameSite=Lax`/`Strict`, scoped paths, no explicit `Domain`.

Sessions can be revoked by the user, an admin, or automatically on password change. Active access tokens are revoked via a short-lived `jti` set checked by middleware.

## OAuth2 authorization server

The service is itself an OAuth2 authorization server. Every application — first-party or third-party — is a registered client with explicit `allowed_scopes` and exact-match `redirect_uris`. This forces internal services to request only the data they need.

- **Authorization Code + PKCE** is the only interactive grant. Implicit and ROPC are not implemented.
- **Client Credentials** covers machine-to-machine flows; mTLS sender-constraining is preferred for refresh tokens.
- **Audience restriction** — every access token names a single resource server in `aud`. Cross-audience use requires token exchange (RFC 8693).
- **Consent** is persisted, user-reviewable, and revocable.

## Authorization

Roles inside an organization are hierarchical: `owner` > `admin` > `member`. Tokens carry `org_id` and role; resource-server middleware verifies, in order:

1. PASETO signature against the cached public key.
2. `iss`, `aud`, `exp`, and `jti` revocation.
3. Required scope for the endpoint.
4. Resource ownership against `org_id`.

## Anti-enumeration

Every public endpoint that touches identity behaves identically for existing and non-existing accounts: login, registration, forgot-password, OIDC callback. There is no standalone "is this username taken" endpoint.

## Auditing

Every security-relevant event — logins, MFA challenges, password changes, session revocations, OAuth grants, organization membership changes — is written to an append-only audit log. Failed-login records hash the attempted username so logs do not become an enumeration oracle. The same log powers user-visible recent-activity views and feeds anomaly detection for step-up authentication.

## Cryptography summary

| Concern | Mechanism |
|---|---|
| Password hashing | Argon2id + server-side pepper |
| Access tokens | PASETO v4.public (Ed25519) |
| Internal/partial tokens | PASETO v4.local (XChaCha20 + BLAKE2b) |
| TOTP secrets, credential blobs at rest | AES-256-GCM with KMS-managed keys |
| Transport | HTTPS-only, HSTS with `includeSubDomains` |
| Key rotation | Scheduled; old public keys retained for the verification overlap window |

---

For internal design notes, threat modeling, and implementation detail, see the project's internal docs.
