// Package auth contains the login orchestrator that routes to the matching
// credential verifier (password, webauthn, oidc, totp) and enforces uniform
// timing, generic errors, and pre-verification rate limiting.
package auth
