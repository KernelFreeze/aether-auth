package account

import (
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrInvalidPasskey means a passkey ceremony value was rejected.
	ErrInvalidPasskey = errors.New("account: invalid passkey")
	// ErrMalformedPasskey means a passkey settings request was malformed.
	ErrMalformedPasskey = errors.New("account: malformed passkey request")
	// ErrExpiredPasskeyChallenge means the passkey ceremony challenge expired.
	ErrExpiredPasskeyChallenge = errors.New("account: expired passkey challenge")
	// ErrReplayedPasskeyChallenge means the passkey challenge was already used.
	ErrReplayedPasskeyChallenge = errors.New("account: replayed passkey challenge")
)

// PasskeyRegistrationBeginRequest starts a passkey registration ceremony.
type PasskeyRegistrationBeginRequest struct {
	AccountID               AccountID
	SessionID               SessionID
	Username                string
	DisplayName             string
	RequestID               string
	UserVerification        string
	AuthenticatorAttachment string
}

// PasskeyRegistrationBegin contains browser-safe WebAuthn creation options.
type PasskeyRegistrationBegin struct {
	ChallengeID string
	Options     json.RawMessage
	ExpiresAt   time.Time
}

// PasskeyRegistrationFinishRequest finishes a passkey registration ceremony.
type PasskeyRegistrationFinishRequest struct {
	AccountID           AccountID
	SessionID           SessionID
	Username            string
	DisplayName         string
	ChallengeID         string
	CredentialName      string
	AttestationResponse json.RawMessage
}

// PasskeyCredential describes a registered passkey without key material.
type PasskeyCredential struct {
	ID          CredentialID
	AccountID   AccountID
	Kind        CredentialKind
	DisplayName string
	Verified    bool
	CreatedAt   time.Time
}
