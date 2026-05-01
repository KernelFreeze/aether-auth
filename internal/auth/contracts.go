package auth

import (
	"context"
	"net/netip"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

// AuthMethod verifies one credential kind for the login orchestrator.
//
// Begin starts any setup needed before verification. Immediate methods such as
// password can return an empty BeginResult. Challenge-based methods such as
// WebAuthn or OIDC should create a one-time challenge, state, nonce, or
// redirect target and return only client-safe data.
//
// Verify proves the credential or challenge response and returns the account,
// credential, factors, and session instructions the orchestrator should apply.
// Implementations may create or link credentials only when the calling feature
// explicitly allows enrollment or account linking. Plain login verification
// must only verify credentials that already belong to the account.
type AuthMethod interface {
	Kind() account.CredentialKind
	Begin(context.Context, BeginRequest) (BeginResult, error)
	Verify(context.Context, VerifyRequest) (AuthResult, error)
}

// BeginRequest carries the trace-safe context shared by every auth method when
// starting a challenge, redirect, or no-op verification setup.
type BeginRequest struct {
	Username         string
	AccountHint      account.AccountID
	Provider         string
	RedirectURI      string
	UserAgent        string
	IP               netip.Addr
	SessionBinding   string
	ChallengeBinding string
	RequestID        string
}

// BeginResult describes setup data safe to return to a client.
type BeginResult struct {
	ChallengePayload map[string]any
	RedirectURL      string
	ChallengeID      string
	ExpiresAt        time.Time
	PublicMetadata   map[string]string
}

// Clone returns a copy of r with map fields detached from the original.
func (r BeginResult) Clone() BeginResult {
	r.ChallengePayload = cloneMap(r.ChallengePayload)
	r.PublicMetadata = cloneStringMap(r.PublicMetadata)
	return r
}

// VerifyRequest carries credential material or challenge responses for an auth
// method. CredentialInput is method-specific and must not be logged.
type VerifyRequest struct {
	CredentialInput any
	ChallengeID     string
	AccountHint     account.AccountID
	Username        string
	MFARequired     bool
	IP              netip.Addr
	UserAgent       string
	PartialSession  *PartialSession
	RequestID       string
}

// PartialSession is the authenticated factor state already proven by an
// in-progress login flow.
type PartialSession struct {
	ID                account.SessionID
	AccountID         account.AccountID
	VerifiedFactors   []account.FactorKind
	ChallengeBindings []string
	ExpiresAt         time.Time
}

// Clone returns a copy of s with slices detached from the original.
func (s PartialSession) Clone() PartialSession {
	s.VerifiedFactors = cloneFactorKinds(s.VerifiedFactors)
	s.ChallengeBindings = cloneStrings(s.ChallengeBindings)
	return s
}

// MFAStatus describes whether the caller should continue into MFA or issue a
// full session after verification.
type MFAStatus string

const (
	// MFAStatusNotRequired means the verified credential is enough to issue a
	// full session.
	MFAStatusNotRequired MFAStatus = "not_required"
	// MFAStatusRequired means more factors are needed before issuing a full
	// session.
	MFAStatusRequired MFAStatus = "required"
	// MFAStatusSatisfied means the required MFA factors are complete.
	MFAStatusSatisfied MFAStatus = "satisfied"
)

// ExternalIdentity contains provider claims safe for account linking or audit
// decisions. Raw provider tokens must not be stored here.
type ExternalIdentity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
	Metadata      map[string]string
}

// Clone returns a copy of i with map fields detached from the original.
func (i ExternalIdentity) Clone() ExternalIdentity {
	i.Metadata = cloneStringMap(i.Metadata)
	return i
}

// AuditMetadata contains trace-safe facts a method wants written to the
// security audit log.
type AuditMetadata struct {
	EventType  string
	RequestID  string
	IP         netip.Addr
	UserAgent  string
	Attributes map[string]string
}

// Clone returns a copy of m with map fields detached from the original.
func (m AuditMetadata) Clone() AuditMetadata {
	m.Attributes = cloneStringMap(m.Attributes)
	return m
}

// SessionIssueInstructions tells the orchestrator which session, if any, to
// issue after a credential is verified.
type SessionIssueInstructions struct {
	Issue       bool
	Partial     bool
	ExpiresAt   time.Time
	Scopes      []string
	Audience    []string
	RedirectURI string
}

// Clone returns a copy of i with slices detached from the original.
func (i SessionIssueInstructions) Clone() SessionIssueInstructions {
	i.Scopes = cloneStrings(i.Scopes)
	i.Audience = cloneStrings(i.Audience)
	return i
}

// AuthResult is the method-independent verification result consumed by the
// login orchestrator.
type AuthResult struct {
	AccountID          account.AccountID
	CredentialID       account.CredentialID
	VerifiedFactors    []account.FactorKind
	MFAStatus          MFAStatus
	ExternalIdentity   *ExternalIdentity
	Audit              AuditMetadata
	Session            SessionIssueInstructions
	PublicMetadata     map[string]string
	CredentialLinked   bool
	CredentialCreated  bool
	CredentialVerified bool
}

// Clone returns a copy of r with pointer, slice, and map fields detached from
// the original.
func (r AuthResult) Clone() AuthResult {
	r.VerifiedFactors = cloneFactorKinds(r.VerifiedFactors)
	if r.ExternalIdentity != nil {
		external := r.ExternalIdentity.Clone()
		r.ExternalIdentity = &external
	}
	r.Audit = r.Audit.Clone()
	r.Session = r.Session.Clone()
	r.PublicMetadata = cloneStringMap(r.PublicMetadata)
	return r
}

func cloneMap[M ~map[string]V, V any](values M) M {
	if values == nil {
		return nil
	}
	cloned := make(M, len(values))
	for k, v := range values {
		cloned[k] = v
	}
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	return cloneMap(values)
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneFactorKinds(values []account.FactorKind) []account.FactorKind {
	return append([]account.FactorKind(nil), values...)
}
