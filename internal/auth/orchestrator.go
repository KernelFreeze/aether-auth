package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

const (
	defaultLoginEndpoint = "/auth/login"

	// AuditEventLoginSucceeded is written after credential verification succeeds.
	AuditEventLoginSucceeded = "auth.login.succeeded"
	// AuditEventLoginFailed is written after a login attempt is rejected.
	AuditEventLoginFailed = "auth.login.failed"
)

// OrchestratorDeps contains the policy collaborators used by Login.
type OrchestratorDeps struct {
	Accounts          AccountRepository
	RateLimiter       RateLimiter
	Audit             AuditWriter
	DummyPasswordWork DummyPasswordWork
	Timing            TimingEqualizer
	Clock             Clock
	LoginEndpoint     string
}

// LoginRequest is the method-independent password/login request consumed by
// the orchestrator. CredentialInput is method-specific and must not be logged.
type LoginRequest struct {
	Kind            account.CredentialKind
	Username        string
	CredentialInput any
	IP              string
	UserAgent       string
	RequestID       string
	PartialSession  *PartialSession
}

// Orchestrator routes auth method setup and verification by credential kind.
type Orchestrator struct {
	methods           map[account.CredentialKind]AuthMethod
	accounts          AccountRepository
	rateLimiter       RateLimiter
	audit             AuditWriter
	dummyPasswordWork DummyPasswordWork
	timing            TimingEqualizer
	clock             Clock
	loginEndpoint     string
}

// NewOrchestrator builds an orchestrator and registers the supplied methods.
func NewOrchestrator(methods ...AuthMethod) (*Orchestrator, error) {
	o := &Orchestrator{methods: make(map[account.CredentialKind]AuthMethod, len(methods))}
	for _, method := range methods {
		if err := o.RegisterMethod(method); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// NewOrchestratorWithDeps builds an orchestrator with login policy
// collaborators and registers the supplied auth methods.
func NewOrchestratorWithDeps(deps OrchestratorDeps, methods ...AuthMethod) (*Orchestrator, error) {
	o, err := NewOrchestrator(methods...)
	if err != nil {
		return nil, err
	}
	o.accounts = deps.Accounts
	o.rateLimiter = deps.RateLimiter
	o.audit = deps.Audit
	o.dummyPasswordWork = deps.DummyPasswordWork
	o.timing = deps.Timing
	o.clock = deps.Clock
	o.loginEndpoint = deps.LoginEndpoint
	if o.loginEndpoint == "" {
		o.loginEndpoint = defaultLoginEndpoint
	}
	return o, nil
}

// RegisterMethod adds one auth method for its credential kind.
func (o *Orchestrator) RegisterMethod(method AuthMethod) error {
	if method == nil {
		return NewServiceError(ErrorKindMalformedInput, "auth method is nil", nil)
	}
	if o.methods == nil {
		o.methods = make(map[account.CredentialKind]AuthMethod)
	}

	kind := method.Kind()
	if !kind.Valid() {
		return NewServiceError(ErrorKindMalformedInput, fmt.Sprintf("auth method has invalid kind %q", kind), nil)
	}
	if _, exists := o.methods[kind]; exists {
		return NewServiceError(ErrorKindMalformedInput, fmt.Sprintf("auth method already registered for %q", kind), nil)
	}

	o.methods[kind] = method
	return nil
}

// Method returns the registered auth method for kind.
func (o *Orchestrator) Method(kind account.CredentialKind) (AuthMethod, bool) {
	if o == nil || o.methods == nil {
		return nil, false
	}
	method, ok := o.methods[kind]
	return method, ok
}

// Begin starts the method-specific setup for kind.
func (o *Orchestrator) Begin(ctx context.Context, kind account.CredentialKind, req BeginRequest) (BeginResult, error) {
	method, err := o.method(kind)
	if err != nil {
		return BeginResult{}, err
	}
	return method.Begin(ctx, req)
}

// Verify verifies credentials or challenge responses for kind.
func (o *Orchestrator) Verify(ctx context.Context, kind account.CredentialKind, req VerifyRequest) (AuthResult, error) {
	method, err := o.method(kind)
	if err != nil {
		return AuthResult{}, err
	}
	return method.Verify(ctx, req)
}

// Login applies the shared public-login policy before and after method-specific
// credential verification.
func (o *Orchestrator) Login(ctx context.Context, req LoginRequest) (AuthResult, error) {
	started := o.started()
	result, err := o.login(ctx, req)
	if waitErr := o.wait(ctx, started); waitErr != nil {
		return AuthResult{}, waitErr
	}
	return result, err
}

func (o *Orchestrator) method(kind account.CredentialKind) (AuthMethod, error) {
	method, ok := o.Method(kind)
	if !ok {
		return nil, NewServiceError(ErrorKindMalformedInput, fmt.Sprintf("auth method not registered for %q", kind), nil)
	}
	return method, nil
}

func (o *Orchestrator) login(ctx context.Context, req LoginRequest) (AuthResult, error) {
	if err := o.readyForLogin(req); err != nil {
		return AuthResult{}, err
	}

	method, err := o.method(req.Kind)
	if err != nil {
		return AuthResult{}, err
	}

	username := normalizeLoginUsername(req.Username)
	snapshot, err := o.accounts.LookupAccount(ctx, AccountLookup{Username: username})
	if err != nil {
		if !isLoginMiss(err) {
			return AuthResult{}, err
		}
		if err := o.checkRateLimit(ctx, req, account.AccountID{}); err != nil {
			return AuthResult{}, o.rejectLogin(ctx, req, account.AccountID{}, account.CredentialID{}, req.Kind, "rate_limited", err)
		}
		if err := o.runDummyPasswordWork(ctx, req); err != nil {
			return AuthResult{}, err
		}
		return AuthResult{}, o.rejectLogin(ctx, req, account.AccountID{}, account.CredentialID{}, req.Kind, "invalid_credentials", ErrInvalidCredentials)
	}

	if err := o.checkRateLimit(ctx, req, snapshot.ID); err != nil {
		return AuthResult{}, o.rejectLogin(ctx, req, snapshot.ID, account.CredentialID{}, req.Kind, "rate_limited", err)
	}

	state, err := o.accounts.AccountState(ctx, snapshot.ID)
	if err != nil {
		return AuthResult{}, err
	}
	if state.Disabled {
		return AuthResult{}, o.rejectLogin(ctx, req, snapshot.ID, account.CredentialID{}, req.Kind, "disabled_account", ErrInvalidCredentials)
	}
	if state.Locked(o.now()) {
		return AuthResult{}, o.rejectLogin(ctx, req, snapshot.ID, account.CredentialID{}, req.Kind, "locked_account", ErrLockedAccount)
	}

	ip, err := parseLoginIP(req.IP)
	if err != nil {
		return AuthResult{}, err
	}
	verifyReq := VerifyRequest{
		CredentialInput: req.CredentialInput,
		AccountHint:     snapshot.ID,
		IP:              ip,
		UserAgent:       req.UserAgent,
		PartialSession:  req.PartialSession,
		RequestID:       req.RequestID,
	}
	result, err := method.Verify(ctx, verifyReq)
	if err != nil {
		return AuthResult{}, o.rejectLogin(ctx, req, snapshot.ID, account.CredentialID{}, req.Kind, auditReason(err), err)
	}
	if result.AccountID.IsZero() {
		result.AccountID = snapshot.ID
	}
	if result.AccountID != snapshot.ID {
		return AuthResult{}, o.rejectLogin(ctx, req, snapshot.ID, result.CredentialID, req.Kind, "account_mismatch", ErrInvalidCredentials)
	}

	if err := o.writeAudit(ctx, loginAuditEvent(req, result.AccountID, result.CredentialID, req.Kind, "success")); err != nil {
		return AuthResult{}, err
	}
	return result.Clone(), nil
}

func (o *Orchestrator) readyForLogin(req LoginRequest) error {
	if o == nil {
		return NewServiceError(ErrorKindInternal, "orchestrator is nil", nil)
	}
	if o.accounts == nil {
		return NewServiceError(ErrorKindInternal, "account repository is nil", nil)
	}
	if o.rateLimiter == nil {
		return NewServiceError(ErrorKindInternal, "rate limiter is nil", nil)
	}
	if o.audit == nil {
		return NewServiceError(ErrorKindInternal, "audit writer is nil", nil)
	}
	if req.Kind == account.CredentialKindPassword && o.dummyPasswordWork == nil {
		return NewServiceError(ErrorKindInternal, "dummy password work is nil", nil)
	}
	if !req.Kind.Valid() {
		return NewServiceError(ErrorKindMalformedInput, "login credential kind is invalid", nil)
	}
	if normalizeLoginUsername(req.Username) == "" {
		return NewServiceError(ErrorKindMalformedInput, "login username is required", nil)
	}
	return nil
}

func (o *Orchestrator) checkRateLimit(ctx context.Context, req LoginRequest, accountID account.AccountID) error {
	result, err := o.rateLimiter.CheckRateLimit(ctx, RateLimitRequest{
		Subject: RateLimitSubject{
			IP:        req.IP,
			AccountID: accountID,
			Username:  normalizeLoginUsername(req.Username),
			Endpoint:  o.endpoint(),
		},
		Cost: 1,
		Now:  o.now(),
	})
	if err != nil {
		return err
	}
	if !result.Allowed {
		return NewServiceError(ErrorKindPolicyDenied, "login rate limit denied", nil)
	}
	return nil
}

func (o *Orchestrator) runDummyPasswordWork(ctx context.Context, req LoginRequest) error {
	if req.Kind != account.CredentialKindPassword {
		return nil
	}
	return o.dummyPasswordWork.RunDummyPasswordWork(ctx, DummyPasswordWorkRequest{
		Username:        normalizeLoginUsername(req.Username),
		CredentialInput: req.CredentialInput,
	})
}

func (o *Orchestrator) rejectLogin(ctx context.Context, req LoginRequest, accountID account.AccountID, credentialID account.CredentialID, kind account.CredentialKind, reason string, err error) error {
	auditErr := o.writeAudit(ctx, loginAuditEvent(req, accountID, credentialID, kind, reason))
	if auditErr != nil {
		return auditErr
	}
	return normalizeLoginError(err)
}

func (o *Orchestrator) writeAudit(ctx context.Context, event AuditEvent) error {
	if o.audit == nil {
		return nil
	}
	return o.audit.WriteAuditEvent(ctx, event)
}

func (o *Orchestrator) endpoint() string {
	if o == nil || o.loginEndpoint == "" {
		return defaultLoginEndpoint
	}
	return o.loginEndpoint
}

func (o *Orchestrator) now() time.Time {
	if o != nil && o.clock != nil {
		return account.NormalizeTimestamp(o.clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}

func (o *Orchestrator) started() time.Time {
	if o == nil || o.timing == nil {
		return time.Time{}
	}
	return o.timing.Started()
}

func (o *Orchestrator) wait(ctx context.Context, started time.Time) error {
	if o == nil || o.timing == nil || started.IsZero() {
		return nil
	}
	return o.timing.Wait(ctx, started)
}

func loginAuditEvent(req LoginRequest, accountID account.AccountID, credentialID account.CredentialID, kind account.CredentialKind, outcome string) AuditEvent {
	eventType := AuditEventLoginFailed
	if outcome == "success" {
		eventType = AuditEventLoginSucceeded
	}
	return AuditEvent{
		Type:         eventType,
		AccountID:    accountID,
		CredentialID: credentialID,
		RequestID:    req.RequestID,
		IP:           req.IP,
		UserAgent:    req.UserAgent,
		Attributes: map[string]string{
			"method":        kind.String(),
			"outcome":       outcome,
			"username_hash": hashLoginUsername(req.Username),
		},
	}
}

func normalizeLoginError(err error) error {
	kind, ok := ErrorKindOf(err)
	if !ok {
		return err
	}
	switch kind {
	case ErrorKindInvalidCredentials, ErrorKindLockedAccount, ErrorKindPolicyDenied:
		return ErrInvalidCredentials
	default:
		return err
	}
}

func auditReason(err error) string {
	kind, ok := ErrorKindOf(err)
	if !ok {
		return "internal_error"
	}
	switch kind {
	case ErrorKindInvalidCredentials:
		return "invalid_credentials"
	case ErrorKindLockedAccount:
		return "locked_account"
	case ErrorKindPolicyDenied:
		return "rate_limited"
	default:
		return string(kind)
	}
}

func isLoginMiss(err error) bool {
	kind, ok := ErrorKindOf(err)
	return ok && kind == ErrorKindInvalidCredentials
}

func normalizeLoginUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func parseLoginIP(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, NewServiceError(ErrorKindMalformedInput, "login ip is malformed", err)
	}
	return ip, nil
}

func hashLoginUsername(username string) string {
	sum := sha256.Sum256([]byte(normalizeLoginUsername(username)))
	return hex.EncodeToString(sum[:])
}
