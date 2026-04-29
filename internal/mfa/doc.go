// Package mfa enforces multi-factor authentication policy: it issues partial
// session tokens after primary auth and gates the upgrade to a full session on
// a second-factor verification.
package mfa
