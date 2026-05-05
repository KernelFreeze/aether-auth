package auth

const (
	// AuditEventMFAFailed is written after a second-factor check is rejected.
	AuditEventMFAFailed = "auth.mfa.failed"
	// AuditEventWebAuthnCloneWarning is written when a passkey assertion does
	// not advance the authenticator sign count.
	AuditEventWebAuthnCloneWarning = "auth.webauthn.clone_warning"
)
