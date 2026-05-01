package auth

import (
	"context"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

// AccountLookup identifies an account by one supported lookup key.
type AccountLookup struct {
	AccountID account.AccountID
	Username  string
	Email     string
}

// AccountSnapshot is the account state needed by login and account-linking
// flows. It intentionally excludes emails, credentials, and profile metadata.
type AccountSnapshot struct {
	ID          account.AccountID
	Username    string
	DisplayName string
	Disabled    bool
	LockedUntil time.Time
	MFARequired bool
	UpdatedAt   time.Time
}

// AccountState is the security state the orchestrator checks before issuing
// sessions or revealing account-specific behavior to an auth method.
type AccountState struct {
	AccountID   account.AccountID
	Disabled    bool
	LockedUntil time.Time
	MFARequired bool
}

// Locked reports whether the account is locked at now.
func (s AccountState) Locked(now time.Time) bool {
	lockedUntil := account.NormalizeTimestamp(s.LockedUntil)
	if lockedUntil.IsZero() {
		return false
	}
	return account.NormalizeTimestamp(now).Before(lockedUntil)
}

// AccountRepository looks up account identity and state for auth flows.
type AccountRepository interface {
	LookupAccount(context.Context, AccountLookup) (AccountSnapshot, error)
	AccountState(context.Context, account.AccountID) (AccountState, error)
}

// CredentialLookup identifies one credential or a set of credentials.
type CredentialLookup struct {
	CredentialID    account.CredentialID
	AccountID       account.AccountID
	Kind            account.CredentialKind
	Provider        string
	ExternalSubject string
}

// CredentialSnapshot is the stored credential data needed by auth methods.
// EncryptedPayload must contain ciphertext only; raw secrets do not belong in
// this type.
type CredentialSnapshot struct {
	ID               account.CredentialID
	AccountID        account.AccountID
	Kind             account.CredentialKind
	Provider         string
	ExternalSubject  string
	EncryptedPayload []byte
	Verified         bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	LastUsedAt       time.Time
}

// CredentialDraft contains the data needed to create a credential.
type CredentialDraft struct {
	AccountID        account.AccountID
	Kind             account.CredentialKind
	Provider         string
	ExternalSubject  string
	EncryptedPayload []byte
	Verified         bool
}

// CredentialUpdate contains mutable credential fields.
type CredentialUpdate struct {
	CredentialID     account.CredentialID
	EncryptedPayload []byte
	Verified         *bool
	LastUsedAt       time.Time
}

// CredentialRepository stores credentials and enforces last-credential rules.
type CredentialRepository interface {
	LookupCredential(context.Context, CredentialLookup) (CredentialSnapshot, error)
	CreateCredential(context.Context, CredentialDraft) (CredentialSnapshot, error)
	UpdateCredential(context.Context, CredentialUpdate) (CredentialSnapshot, error)
	CanRemoveCredential(context.Context, account.AccountID, account.CredentialID) (bool, error)
}

// ChallengePurpose describes why a challenge exists.
type ChallengePurpose string

const (
	// ChallengePurposeWebAuthn stores a WebAuthn registration or assertion challenge.
	ChallengePurposeWebAuthn ChallengePurpose = "webauthn"
	// ChallengePurposeOIDCState stores the OAuth2 state value.
	ChallengePurposeOIDCState ChallengePurpose = "oidc_state"
	// ChallengePurposeOIDCNonce stores the OIDC nonce bound to an ID token.
	ChallengePurposeOIDCNonce ChallengePurpose = "oidc_nonce"
	// ChallengePurposeOIDCPKCE stores the PKCE verifier for an OIDC flow.
	ChallengePurposeOIDCPKCE ChallengePurpose = "oidc_pkce"
)

// StoredChallenge is a one-time challenge record with an exclusive expiry.
type StoredChallenge struct {
	ID             string
	Purpose        ChallengePurpose
	AccountID      account.AccountID
	CredentialID   account.CredentialID
	Provider       string
	SessionBinding string
	RequestID      string
	Payload        []byte
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// ChallengeLookup identifies a stored challenge and the binding expected by
// the caller consuming it.
type ChallengeLookup struct {
	ID             string
	Purpose        ChallengePurpose
	SessionBinding string
	Provider       string
}

// ChallengeStore owns one-time challenge persistence and TTL cleanup.
type ChallengeStore interface {
	SaveChallenge(context.Context, StoredChallenge) error
	ConsumeChallenge(context.Context, ChallengeLookup) (StoredChallenge, error)
	DeleteExpiredChallenges(context.Context, time.Time) error
}

// PartialSessionState records the factors proven before a login flow completes.
type PartialSessionState struct {
	SessionID         account.SessionID
	AccountID         account.AccountID
	VerifiedFactors   []account.FactorKind
	ChallengeBindings []string
	ExpiresAt         time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// FactorStore persists partial-session factor state.
type FactorStore interface {
	SavePartialSession(context.Context, PartialSessionState) error
	GetPartialSession(context.Context, account.SessionID) (PartialSessionState, error)
	AddVerifiedFactor(context.Context, account.SessionID, account.FactorKind, string) (PartialSessionState, error)
	DeletePartialSession(context.Context, account.SessionID) error
}

// SessionIssueRequest contains the security facts needed to create a full
// session and its tokens.
type SessionIssueRequest struct {
	AccountID       account.AccountID
	ClientID        account.ClientID
	VerifiedFactors []account.FactorKind
	Scopes          []string
	Audience        []string
	IP              string
	UserAgent       string
	Now             time.Time
}

// SessionIssueResult contains client-deliverable session material.
type SessionIssueResult struct {
	SessionID    account.SessionID
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// PartialSessionIssueRequest contains the data needed to create an MFA-bound
// partial session.
type PartialSessionIssueRequest struct {
	AccountID         account.AccountID
	VerifiedFactors   []account.FactorKind
	ChallengeBindings []string
	TTL               time.Duration
	Now               time.Time
}

// PartialSessionIssueResult contains the token and stored state for a partial
// login session.
type PartialSessionIssueResult struct {
	SessionID account.SessionID
	Token     string
	ExpiresAt time.Time
}

// SessionIssuer creates partial and full login sessions.
type SessionIssuer interface {
	IssueSession(context.Context, SessionIssueRequest) (SessionIssueResult, error)
	IssuePartialSession(context.Context, PartialSessionIssueRequest) (PartialSessionIssueResult, error)
}

// AuditEvent is a security-relevant event safe to write to the audit log.
type AuditEvent struct {
	Type         string
	AccountID    account.AccountID
	CredentialID account.CredentialID
	SessionID    account.SessionID
	RequestID    string
	IP           string
	UserAgent    string
	OccurredAt   time.Time
	Attributes   map[string]string
}

// AuditWriter records security events.
type AuditWriter interface {
	WriteAuditEvent(context.Context, AuditEvent) error
}

// RateLimitSubject identifies a bucket to check before sensitive work starts.
type RateLimitSubject struct {
	IP        string
	AccountID account.AccountID
	Username  string
	Endpoint  string
}

// RateLimitRequest describes one rate-limit decision.
type RateLimitRequest struct {
	Subject RateLimitSubject
	Cost    int
	Now     time.Time
}

// RateLimitResult reports whether a request may continue.
type RateLimitResult struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAt    time.Time
}

// RateLimiter checks IP, account, and endpoint buckets before verification.
type RateLimiter interface {
	CheckRateLimit(context.Context, RateLimitRequest) (RateLimitResult, error)
}

// DummyPasswordWork runs equivalent password hashing work when a username is
// missing so public login timing does not reveal account existence.
type DummyPasswordWork interface {
	RunDummyPasswordWork(context.Context, DummyPasswordWorkRequest) error
}

// DummyPasswordWorkRequest contains credential input for a dummy password
// verification. CredentialInput may contain a plaintext password and must not
// be logged.
type DummyPasswordWorkRequest struct {
	Username        string
	CredentialInput any
}

// TimingEqualizer pads account-sensitive operations to a shared minimum
// duration.
type TimingEqualizer interface {
	Started() time.Time
	Wait(context.Context, time.Time) error
}

// Clock provides deterministic time in tests.
type Clock interface {
	Now() time.Time
}

// RandomReader provides cryptographic randomness and deterministic test bytes.
type RandomReader interface {
	Read([]byte) (int, error)
}

// IDGenerator creates the typed IDs used across auth flows.
type IDGenerator interface {
	NewAccountID() (account.AccountID, error)
	NewCredentialID() (account.CredentialID, error)
	NewSessionID() (account.SessionID, error)
	NewOrganizationID() (account.OrganizationID, error)
	NewClientID() (account.ClientID, error)
	NewChallengeID() (string, error)
}

// PasswordHash is the PHC string and metadata stored for a password.
type PasswordHash struct {
	PHCString string `json:"phc_string"`
	ParamsID  string `json:"params_id"`
}

// PasswordHashRequest contains a plaintext password. Callers must not log it.
type PasswordHashRequest struct {
	Password  string
	AccountID account.AccountID
}

// PasswordVerifyRequest contains a plaintext password and stored hash.
type PasswordVerifyRequest struct {
	Password  string
	Hash      PasswordHash
	AccountID account.AccountID
}

// PasswordVerifyResult reports a password comparison.
type PasswordVerifyResult struct {
	Matched     bool
	NeedsRehash bool
}

// PasswordHasher hashes and verifies passwords.
type PasswordHasher interface {
	HashPassword(context.Context, PasswordHashRequest) (PasswordHash, error)
	VerifyPassword(context.Context, PasswordVerifyRequest) (PasswordVerifyResult, error)
}

// PasswordPolicyRequest contains the proposed password and account context.
type PasswordPolicyRequest struct {
	Password  string
	AccountID account.AccountID
	Username  string
	Email     string
}

// PasswordPolicyResult reports policy violations without exposing secrets.
type PasswordPolicyResult struct {
	Allowed    bool
	Violations []string
}

// PasswordPolicy checks local password rules.
type PasswordPolicy interface {
	CheckPasswordPolicy(context.Context, PasswordPolicyRequest) (PasswordPolicyResult, error)
}

// PasswordBreachRequest contains a password to check against a breach corpus.
type PasswordBreachRequest struct {
	Password  string
	AccountID account.AccountID
}

// PasswordBreachResult reports whether a password appears in the breach corpus.
type PasswordBreachResult struct {
	Breached bool
	Count    int
}

// BreachChecker checks passwords against a breach corpus.
type BreachChecker interface {
	CheckPasswordBreach(context.Context, PasswordBreachRequest) (PasswordBreachResult, error)
}

// SecretBoxSealRequest contains plaintext credential data. Callers must not log
// Plaintext or associated data that includes secrets.
type SecretBoxSealRequest struct {
	Plaintext      []byte
	AssociatedData []byte
	KeyID          string
}

// SecretBoxPayload contains encrypted credential data and the metadata needed
// to decrypt it later.
type SecretBoxPayload struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

// SecretBoxOpenRequest contains encrypted credential data to decrypt.
type SecretBoxOpenRequest struct {
	Payload        SecretBoxPayload
	AssociatedData []byte
}

// SecretBox encrypts credential payloads for storage. Production
// implementations must use AES-256-GCM.
type SecretBox interface {
	Seal(context.Context, SecretBoxSealRequest) (SecretBoxPayload, error)
	Open(context.Context, SecretBoxOpenRequest) ([]byte, error)
}
