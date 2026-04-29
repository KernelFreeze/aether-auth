// Package paseto wraps PASETO v4.public (Ed25519) and v4.local (XChaCha20 +
// BLAKE2b) issuance and verification. The keystore exposes the active signing
// key plus older verification keys to support rotation.
package paseto
