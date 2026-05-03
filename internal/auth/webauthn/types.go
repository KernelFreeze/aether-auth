package webauthn

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

const defaultRelyingPartyName = "Aether Auth"

// UserVerificationRequirement describes whether an authenticator must prove
// local user verification.
type UserVerificationRequirement string

const (
	// UserVerificationRequired requires local user verification.
	UserVerificationRequired UserVerificationRequirement = "required"
	// UserVerificationPreferred asks for local user verification when available.
	UserVerificationPreferred UserVerificationRequirement = "preferred"
	// UserVerificationDiscouraged does not require local user verification.
	UserVerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// AuthenticatorAttachment narrows which authenticator attachment type may be
// used during registration.
type AuthenticatorAttachment string

const (
	// AuthenticatorAttachmentPlatform selects a platform authenticator.
	AuthenticatorAttachmentPlatform AuthenticatorAttachment = "platform"
	// AuthenticatorAttachmentCrossPlatform selects a roaming authenticator.
	AuthenticatorAttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Config controls the WebAuthn relying party wrapper.
type Config struct {
	RelyingPartyID      string
	RelyingPartyName    string
	RelyingPartyOrigins []string
	UserVerification    UserVerificationRequirement
	LoginTimeout        time.Duration
	RegistrationTimeout time.Duration
	EnforceTimeouts     bool
}

// User is the Aether account shape passed into WebAuthn ceremonies.
type User struct {
	AccountID   account.AccountID
	Username    string
	DisplayName string
	Credentials []Credential
}

// WebAuthnID returns the stable account handle WebAuthn signs over.
func (u User) WebAuthnID() []byte {
	if u.AccountID.IsZero() {
		return nil
	}
	return []byte(u.AccountID.String())
}

// WebAuthnName returns the account username shown by browser authenticators.
func (u User) WebAuthnName() string {
	return strings.TrimSpace(u.Username)
}

// WebAuthnDisplayName returns the display name shown by browser authenticators.
func (u User) WebAuthnDisplayName() string {
	if displayName := strings.TrimSpace(u.DisplayName); displayName != "" {
		return displayName
	}
	return u.WebAuthnName()
}

// WebAuthnIcon is deprecated by the WebAuthn spec and intentionally blank.
func (u User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns all ready credentials on the user. Relying party
// filtering is applied by the Server methods before validation.
func (u User) WebAuthnCredentials() []gowebauthn.Credential {
	return credentialsToWebAuthn(u.Credentials)
}

// Credential is the passkey material stored beside an Aether credential row.
type Credential struct {
	ID                      account.CredentialID
	AccountID               account.AccountID
	KeyID                   []byte
	PublicKey               []byte
	AttestationType         string
	Transports              []protocol.AuthenticatorTransport
	AAGUID                  []byte
	SignCount               uint32
	RelyingPartyID          string
	UserVerified            bool
	BackupEligible          bool
	BackedUp                bool
	AuthenticatorAttachment AuthenticatorAttachment
	DisplayName             string
	Verified                bool
	CreatedAt               time.Time
	UpdatedAt               time.Time
	LastUsedAt              time.Time
}

// Ready reports whether the credential has enough verified material to be used
// in an assertion ceremony.
func (c Credential) Ready() bool {
	return c.Verified && len(c.KeyID) > 0 && len(c.PublicKey) > 0 && strings.TrimSpace(c.RelyingPartyID) != ""
}

// WebAuthnCredential converts an Aether credential to the go-webauthn shape.
func (c Credential) WebAuthnCredential() gowebauthn.Credential {
	return gowebauthn.Credential{
		ID:              cloneBytes(c.KeyID),
		PublicKey:       cloneBytes(c.PublicKey),
		AttestationType: c.AttestationType,
		Transport:       append([]protocol.AuthenticatorTransport(nil), c.Transports...),
		Flags: gowebauthn.CredentialFlags{
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackedUp,
		},
		Authenticator: gowebauthn.Authenticator{
			AAGUID:     cloneBytes(c.AAGUID),
			SignCount:  c.SignCount,
			Attachment: c.AuthenticatorAttachment.protocol(),
		},
	}
}

// CredentialsForRelyingParty returns ready credentials bound to rpID.
func CredentialsForRelyingParty(credentials []Credential, rpID string) []gowebauthn.Credential {
	rpID = strings.TrimSpace(rpID)
	filtered := make([]Credential, 0, len(credentials))
	for _, credential := range credentials {
		if !credential.Ready() {
			continue
		}
		if rpID != "" && credential.RelyingPartyID != rpID {
			continue
		}
		filtered = append(filtered, credential)
	}
	return credentialsToWebAuthn(filtered)
}

// FindCredentialByKeyID returns the Aether credential with the WebAuthn key ID.
func FindCredentialByKeyID(credentials []Credential, keyID []byte) (Credential, bool) {
	for _, credential := range credentials {
		if bytes.Equal(credential.KeyID, keyID) {
			return credential, true
		}
	}
	return Credential{}, false
}

// Challenge is the session data that must be stored between WebAuthn begin and
// finish calls.
type Challenge struct {
	Challenge            string
	AccountID            account.AccountID
	UserHandle           []byte
	AllowedCredentialIDs [][]byte
	UserVerification     UserVerificationRequirement
	RelyingPartyID       string
	ExpiresAt            time.Time
	CreatedAt            time.Time
}

// Encode serializes the challenge for storage in Aether's challenge table.
func (c Challenge) Encode() ([]byte, error) {
	return json.Marshal(c)
}

// DecodeChallenge parses a stored WebAuthn challenge payload.
func DecodeChallenge(payload []byte) (Challenge, error) {
	var challenge Challenge
	if err := json.Unmarshal(payload, &challenge); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func challengeFromSession(accountID account.AccountID, rpID string, session *gowebauthn.SessionData) Challenge {
	if session == nil {
		return Challenge{}
	}
	return Challenge{
		Challenge:            session.Challenge,
		AccountID:            accountID,
		UserHandle:           cloneBytes(session.UserID),
		AllowedCredentialIDs: cloneByteSlices(session.AllowedCredentialIDs),
		UserVerification:     userVerificationFromProtocol(session.UserVerification),
		RelyingPartyID:       rpID,
		ExpiresAt:            account.NormalizeTimestamp(session.Expires),
		CreatedAt:            account.NormalizeTimestamp(time.Now()),
	}
}

func (c Challenge) sessionData() gowebauthn.SessionData {
	return gowebauthn.SessionData{
		Challenge:            c.Challenge,
		UserID:               cloneBytes(c.UserHandle),
		AllowedCredentialIDs: cloneByteSlices(c.AllowedCredentialIDs),
		Expires:              account.NormalizeTimestamp(c.ExpiresAt),
		UserVerification:     c.UserVerification.protocol(),
	}
}

func credentialsToWebAuthn(credentials []Credential) []gowebauthn.Credential {
	converted := make([]gowebauthn.Credential, 0, len(credentials))
	for _, credential := range credentials {
		if !credential.Ready() {
			continue
		}
		converted = append(converted, credential.WebAuthnCredential())
	}
	return converted
}

func userVerificationFromProtocol(verification protocol.UserVerificationRequirement) UserVerificationRequirement {
	switch verification {
	case protocol.VerificationRequired:
		return UserVerificationRequired
	case protocol.VerificationDiscouraged:
		return UserVerificationDiscouraged
	default:
		return UserVerificationPreferred
	}
}

func (v UserVerificationRequirement) protocol() protocol.UserVerificationRequirement {
	switch v {
	case UserVerificationRequired:
		return protocol.VerificationRequired
	case UserVerificationDiscouraged:
		return protocol.VerificationDiscouraged
	default:
		return protocol.VerificationPreferred
	}
}

func (a AuthenticatorAttachment) protocol() protocol.AuthenticatorAttachment {
	switch a {
	case AuthenticatorAttachmentPlatform:
		return protocol.Platform
	case AuthenticatorAttachmentCrossPlatform:
		return protocol.CrossPlatform
	default:
		return ""
	}
}

func authenticatorAttachmentFromProtocol(attachment protocol.AuthenticatorAttachment) AuthenticatorAttachment {
	switch attachment {
	case protocol.Platform:
		return AuthenticatorAttachmentPlatform
	case protocol.CrossPlatform:
		return AuthenticatorAttachmentCrossPlatform
	default:
		return ""
	}
}

func cloneBytes(values []byte) []byte {
	if values == nil {
		return nil
	}
	return append([]byte(nil), values...)
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for i := range values {
		cloned[i] = cloneBytes(values[i])
	}
	return cloned
}

type webUser struct {
	User
	credentials []gowebauthn.Credential
}

func (u webUser) WebAuthnCredentials() []gowebauthn.Credential {
	return append([]gowebauthn.Credential(nil), u.credentials...)
}
