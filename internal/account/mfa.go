package account

import (
	"errors"
)

var (
	// ErrInvalidMFA means an MFA setup or verification value was rejected.
	ErrInvalidMFA = errors.New("account: invalid mfa")
	// ErrMalformedMFA means an account MFA settings request was malformed.
	ErrMalformedMFA = errors.New("account: malformed mfa request")
)

// TOTPEnrollmentRequest describes a TOTP setup request from account settings.
type TOTPEnrollmentRequest struct {
	AccountID   AccountID
	Issuer      string
	AccountName string
}

// TOTPEnrollment is the one-time TOTP setup material returned to the client.
type TOTPEnrollment struct {
	AccountID       AccountID
	CredentialID    CredentialID
	Secret          string
	ProvisioningURI string
}

// TOTPConfirmRequest verifies a newly enrolled TOTP credential.
type TOTPConfirmRequest struct {
	AccountID    AccountID
	CredentialID CredentialID
	Code         string
	Endpoint     string
}

// TOTPCredential describes the confirmed TOTP credential without secret data.
type TOTPCredential struct {
	ID        CredentialID
	AccountID AccountID
	Kind      CredentialKind
	Verified  bool
}

// RecoveryCodeGenerateRequest requests a replacement recovery-code set.
type RecoveryCodeGenerateRequest struct {
	AccountID    AccountID
	CredentialID CredentialID
}

// GeneratedRecoveryCodes contains raw recovery codes returned once.
type GeneratedRecoveryCodes struct {
	AccountID    AccountID
	CredentialID CredentialID
	Codes        []string
}
