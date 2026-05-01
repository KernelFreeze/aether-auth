package account

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AccountID identifies an account. New account IDs should be UUIDv7 values so
// primary keys remain opaque while preserving insertion locality.
type AccountID uuid.UUID

// CredentialID identifies a credential attached to an account.
type CredentialID uuid.UUID

// SessionID identifies a partial or full login session.
type SessionID uuid.UUID

// OrganizationID identifies an organization tenant.
type OrganizationID uuid.UUID

// ClientID identifies an OAuth client.
type ClientID uuid.UUID

// NewAccountID returns a new UUIDv7 account ID.
func NewAccountID() (AccountID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return AccountID(uuid.Nil), fmt.Errorf("account: generate account id: %w", err)
	}
	return AccountID(id), nil
}

// ParseAccountID parses a non-nil UUID account ID.
func ParseAccountID(value string) (AccountID, error) {
	id, err := parseID(value, "account id")
	if err != nil {
		return AccountID(uuid.Nil), err
	}
	return AccountID(id), nil
}

// UUID returns the underlying UUID value.
func (id AccountID) UUID() uuid.UUID {
	return uuid.UUID(id)
}

// String returns the canonical UUID string.
func (id AccountID) String() string {
	return id.UUID().String()
}

// IsZero reports whether the ID has not been set.
func (id AccountID) IsZero() bool {
	return id.UUID() == uuid.Nil
}

// MarshalText encodes the ID as a canonical UUID string.
func (id AccountID) MarshalText() ([]byte, error) {
	return id.UUID().MarshalText()
}

// UnmarshalText decodes a non-nil canonical UUID string.
func (id *AccountID) UnmarshalText(text []byte) error {
	parsed, err := parseID(string(text), "account id")
	if err != nil {
		return err
	}
	*id = AccountID(parsed)
	return nil
}

// NewCredentialID returns a new UUIDv7 credential ID.
func NewCredentialID() (CredentialID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return CredentialID(uuid.Nil), fmt.Errorf("account: generate credential id: %w", err)
	}
	return CredentialID(id), nil
}

// ParseCredentialID parses a non-nil UUID credential ID.
func ParseCredentialID(value string) (CredentialID, error) {
	id, err := parseID(value, "credential id")
	if err != nil {
		return CredentialID(uuid.Nil), err
	}
	return CredentialID(id), nil
}

// UUID returns the underlying UUID value.
func (id CredentialID) UUID() uuid.UUID {
	return uuid.UUID(id)
}

// String returns the canonical UUID string.
func (id CredentialID) String() string {
	return id.UUID().String()
}

// IsZero reports whether the ID has not been set.
func (id CredentialID) IsZero() bool {
	return id.UUID() == uuid.Nil
}

// MarshalText encodes the ID as a canonical UUID string.
func (id CredentialID) MarshalText() ([]byte, error) {
	return id.UUID().MarshalText()
}

// UnmarshalText decodes a non-nil canonical UUID string.
func (id *CredentialID) UnmarshalText(text []byte) error {
	parsed, err := parseID(string(text), "credential id")
	if err != nil {
		return err
	}
	*id = CredentialID(parsed)
	return nil
}

// NewSessionID returns a new UUIDv7 session ID.
func NewSessionID() (SessionID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return SessionID(uuid.Nil), fmt.Errorf("account: generate session id: %w", err)
	}
	return SessionID(id), nil
}

// ParseSessionID parses a non-nil UUID session ID.
func ParseSessionID(value string) (SessionID, error) {
	id, err := parseID(value, "session id")
	if err != nil {
		return SessionID(uuid.Nil), err
	}
	return SessionID(id), nil
}

// UUID returns the underlying UUID value.
func (id SessionID) UUID() uuid.UUID {
	return uuid.UUID(id)
}

// String returns the canonical UUID string.
func (id SessionID) String() string {
	return id.UUID().String()
}

// IsZero reports whether the ID has not been set.
func (id SessionID) IsZero() bool {
	return id.UUID() == uuid.Nil
}

// MarshalText encodes the ID as a canonical UUID string.
func (id SessionID) MarshalText() ([]byte, error) {
	return id.UUID().MarshalText()
}

// UnmarshalText decodes a non-nil canonical UUID string.
func (id *SessionID) UnmarshalText(text []byte) error {
	parsed, err := parseID(string(text), "session id")
	if err != nil {
		return err
	}
	*id = SessionID(parsed)
	return nil
}

// NewOrganizationID returns a new UUIDv7 organization ID.
func NewOrganizationID() (OrganizationID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return OrganizationID(uuid.Nil), fmt.Errorf("account: generate organization id: %w", err)
	}
	return OrganizationID(id), nil
}

// ParseOrganizationID parses a non-nil UUID organization ID.
func ParseOrganizationID(value string) (OrganizationID, error) {
	id, err := parseID(value, "organization id")
	if err != nil {
		return OrganizationID(uuid.Nil), err
	}
	return OrganizationID(id), nil
}

// UUID returns the underlying UUID value.
func (id OrganizationID) UUID() uuid.UUID {
	return uuid.UUID(id)
}

// String returns the canonical UUID string.
func (id OrganizationID) String() string {
	return id.UUID().String()
}

// IsZero reports whether the ID has not been set.
func (id OrganizationID) IsZero() bool {
	return id.UUID() == uuid.Nil
}

// MarshalText encodes the ID as a canonical UUID string.
func (id OrganizationID) MarshalText() ([]byte, error) {
	return id.UUID().MarshalText()
}

// UnmarshalText decodes a non-nil canonical UUID string.
func (id *OrganizationID) UnmarshalText(text []byte) error {
	parsed, err := parseID(string(text), "organization id")
	if err != nil {
		return err
	}
	*id = OrganizationID(parsed)
	return nil
}

// NewClientID returns a new UUIDv7 OAuth client ID.
func NewClientID() (ClientID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return ClientID(uuid.Nil), fmt.Errorf("account: generate client id: %w", err)
	}
	return ClientID(id), nil
}

// ParseClientID parses a non-nil UUID OAuth client ID.
func ParseClientID(value string) (ClientID, error) {
	id, err := parseID(value, "client id")
	if err != nil {
		return ClientID(uuid.Nil), err
	}
	return ClientID(id), nil
}

// UUID returns the underlying UUID value.
func (id ClientID) UUID() uuid.UUID {
	return uuid.UUID(id)
}

// String returns the canonical UUID string.
func (id ClientID) String() string {
	return id.UUID().String()
}

// IsZero reports whether the ID has not been set.
func (id ClientID) IsZero() bool {
	return id.UUID() == uuid.Nil
}

// MarshalText encodes the ID as a canonical UUID string.
func (id ClientID) MarshalText() ([]byte, error) {
	return id.UUID().MarshalText()
}

// UnmarshalText decodes a non-nil canonical UUID string.
func (id *ClientID) UnmarshalText(text []byte) error {
	parsed, err := parseID(string(text), "client id")
	if err != nil {
		return err
	}
	*id = ClientID(parsed)
	return nil
}

// CredentialKind names a stored credential verifier.
type CredentialKind string

const (
	// CredentialKindPassword verifies a password hash.
	CredentialKindPassword CredentialKind = "password"
	// CredentialKindWebAuthn verifies a WebAuthn/FIDO2 passkey.
	CredentialKindWebAuthn CredentialKind = "webauthn"
	// CredentialKindOIDC verifies an external OIDC identity.
	CredentialKindOIDC CredentialKind = "oidc"
	// CredentialKindTOTP verifies a TOTP secret.
	CredentialKindTOTP CredentialKind = "totp"
	// CredentialKindRecoveryCode verifies a one-time MFA recovery code.
	CredentialKindRecoveryCode CredentialKind = "recovery_code"
)

var credentialKinds = []CredentialKind{
	CredentialKindPassword,
	CredentialKindWebAuthn,
	CredentialKindOIDC,
	CredentialKindTOTP,
	CredentialKindRecoveryCode,
}

// CredentialKinds returns every supported credential kind.
func CredentialKinds() []CredentialKind {
	return append([]CredentialKind(nil), credentialKinds...)
}

// ParseCredentialKind parses a credential kind.
func ParseCredentialKind(value string) (CredentialKind, error) {
	kind := CredentialKind(value)
	if !kind.Valid() {
		return "", fmt.Errorf("account: invalid credential kind %q", value)
	}
	return kind, nil
}

// String returns the wire value for the credential kind.
func (k CredentialKind) String() string {
	return string(k)
}

// Valid reports whether k is a supported credential kind.
func (k CredentialKind) Valid() bool {
	switch k {
	case CredentialKindPassword,
		CredentialKindWebAuthn,
		CredentialKindOIDC,
		CredentialKindTOTP,
		CredentialKindRecoveryCode:
		return true
	default:
		return false
	}
}

// FactorKind names an authentication factor proven during a login flow.
type FactorKind string

const (
	// FactorKindUser records that the account identity has been selected.
	FactorKindUser FactorKind = "user"
	// FactorKindPassword records successful password verification.
	FactorKindPassword FactorKind = "password"
	// FactorKindPasskey records successful passkey verification.
	FactorKindPasskey FactorKind = "passkey"
	// FactorKindIDP records successful external identity-provider verification.
	FactorKindIDP FactorKind = "idp"
	// FactorKindTOTP records successful TOTP verification.
	FactorKindTOTP FactorKind = "totp"
	// FactorKindRecoveryCode records successful recovery-code verification.
	FactorKindRecoveryCode FactorKind = "recovery_code"
)

var factorKinds = []FactorKind{
	FactorKindUser,
	FactorKindPassword,
	FactorKindPasskey,
	FactorKindIDP,
	FactorKindTOTP,
	FactorKindRecoveryCode,
}

// FactorKinds returns every supported authentication factor kind.
func FactorKinds() []FactorKind {
	return append([]FactorKind(nil), factorKinds...)
}

// ParseFactorKind parses an authentication factor kind.
func ParseFactorKind(value string) (FactorKind, error) {
	kind := FactorKind(value)
	if !kind.Valid() {
		return "", fmt.Errorf("account: invalid factor kind %q", value)
	}
	return kind, nil
}

// String returns the wire value for the factor kind.
func (k FactorKind) String() string {
	return string(k)
}

// Valid reports whether k is a supported authentication factor kind.
func (k FactorKind) Valid() bool {
	switch k {
	case FactorKindUser,
		FactorKindPassword,
		FactorKindPasskey,
		FactorKindIDP,
		FactorKindTOTP,
		FactorKindRecoveryCode:
		return true
	default:
		return false
	}
}

// Timestamps stores the common create/update timestamps for persisted account
// domain records. Values must be stored in UTC.
type Timestamps struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Expiry stores an exclusive expiration instant. An item is expired when the
// current time is equal to or after ExpiresAt.
type Expiry struct {
	ExpiresAt time.Time
}

// NewExpiry returns an expiry timestamp ttl after now.
func NewExpiry(now time.Time, ttl time.Duration) Expiry {
	return Expiry{ExpiresAt: NormalizeTimestamp(now).Add(ttl)}
}

// IsExpired reports whether the expiry has elapsed. A zero ExpiresAt is
// treated as expired so challenges and sessions fail closed.
func (e Expiry) IsExpired(now time.Time) bool {
	return IsExpired(now, e.ExpiresAt)
}

// Remaining returns the duration until expiry, or zero when already expired.
func (e Expiry) Remaining(now time.Time) time.Duration {
	if e.IsExpired(now) {
		return 0
	}
	return NormalizeTimestamp(e.ExpiresAt).Sub(NormalizeTimestamp(now))
}

// NormalizeTimestamp strips monotonic clock data and converts non-zero times to
// UTC before storing, signing, or comparing domain timestamps.
func NormalizeTimestamp(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Round(0)
}

// IsExpired applies the shared exclusive-expiry convention. A zero expiresAt is
// treated as expired.
func IsExpired(now, expiresAt time.Time) bool {
	expiresAt = NormalizeTimestamp(expiresAt)
	if expiresAt.IsZero() {
		return true
	}
	return !NormalizeTimestamp(now).Before(expiresAt)
}

func parseID(value, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("account: parse %s: %w", name, err)
	}
	if id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("account: %s must not be nil UUID", name)
	}
	return id, nil
}
