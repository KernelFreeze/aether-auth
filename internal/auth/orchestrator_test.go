package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

func TestOrchestratorRegistersAndCallsFakeMethods(t *testing.T) {
	accountID, credentialID := mustAuthIDs(t)
	ip := netip.MustParseAddr("203.0.113.10")

	password := fakeAuthMethod{
		kind: account.CredentialKindPassword,
		begin: func(_ context.Context, req BeginRequest) (BeginResult, error) {
			if req.Username != "celeste" {
				t.Fatalf("password username = %q, want celeste", req.Username)
			}
			return BeginResult{PublicMetadata: map[string]string{"method": "password"}}, nil
		},
		verify: func(_ context.Context, req VerifyRequest) (AuthResult, error) {
			if req.AccountHint != accountID {
				t.Fatalf("password account hint = %v, want %v", req.AccountHint, accountID)
			}
			return AuthResult{
				AccountID:       accountID,
				CredentialID:    credentialID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
				MFAStatus:       MFAStatusNotRequired,
				Session:         SessionIssueInstructions{Issue: true},
			}, nil
		},
	}
	webauthn := fakeAuthMethod{
		kind: account.CredentialKindWebAuthn,
		begin: func(context.Context, BeginRequest) (BeginResult, error) {
			return BeginResult{ChallengeID: "webauthn-challenge"}, nil
		},
		verify: func(_ context.Context, req VerifyRequest) (AuthResult, error) {
			if req.ChallengeID != "webauthn-challenge" {
				t.Fatalf("webauthn challenge ID = %q, want webauthn-challenge", req.ChallengeID)
			}
			return AuthResult{
				AccountID:       accountID,
				CredentialID:    credentialID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPasskey},
				MFAStatus:       MFAStatusSatisfied,
				Session:         SessionIssueInstructions{Issue: true},
			}, nil
		},
	}

	orchestrator, err := NewOrchestrator(password, webauthn)
	if err != nil {
		t.Fatalf("new orchestrator: %v", err)
	}
	if _, ok := orchestrator.Method(account.CredentialKindPassword); !ok {
		t.Fatal("password method should be registered")
	}
	if _, ok := orchestrator.Method(account.CredentialKindWebAuthn); !ok {
		t.Fatal("webauthn method should be registered")
	}

	begin, err := orchestrator.Begin(context.Background(), account.CredentialKindPassword, BeginRequest{
		Username:  "celeste",
		IP:        ip,
		UserAgent: "Mozilla/5.0",
		RequestID: "req-123",
	})
	if err != nil {
		t.Fatalf("begin password: %v", err)
	}
	if begin.PublicMetadata["method"] != "password" {
		t.Fatalf("begin method metadata = %q, want password", begin.PublicMetadata["method"])
	}

	result, err := orchestrator.Verify(context.Background(), account.CredentialKindPassword, VerifyRequest{
		AccountHint: accountID,
		IP:          ip,
		UserAgent:   "Mozilla/5.0",
		RequestID:   "req-123",
	})
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if result.AccountID != accountID || result.CredentialID != credentialID {
		t.Fatalf("verify result IDs = %v/%v, want %v/%v", result.AccountID, result.CredentialID, accountID, credentialID)
	}
	if !result.Session.Issue {
		t.Fatal("password method should request session issuance")
	}

	challenge, err := orchestrator.Begin(context.Background(), account.CredentialKindWebAuthn, BeginRequest{})
	if err != nil {
		t.Fatalf("begin webauthn: %v", err)
	}
	if _, err := orchestrator.Verify(context.Background(), account.CredentialKindWebAuthn, VerifyRequest{ChallengeID: challenge.ChallengeID}); err != nil {
		t.Fatalf("verify webauthn: %v", err)
	}
}

func TestOrchestratorRejectsDuplicateAndMissingMethods(t *testing.T) {
	method := fakeAuthMethod{
		kind:   account.CredentialKindPassword,
		begin:  func(context.Context, BeginRequest) (BeginResult, error) { return BeginResult{}, nil },
		verify: func(context.Context, VerifyRequest) (AuthResult, error) { return AuthResult{}, nil },
	}

	orchestrator, err := NewOrchestrator(method)
	if err != nil {
		t.Fatalf("new orchestrator: %v", err)
	}
	if err := orchestrator.RegisterMethod(method); !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("duplicate register error = %v, want malformed input", err)
	}
	if _, err := orchestrator.Begin(context.Background(), account.CredentialKindOIDC, BeginRequest{}); !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("missing method error = %v, want malformed input", err)
	}
}

func TestLoginPublicErrorHidesAccountExistenceAndLockout(t *testing.T) {
	accountLookup := NewServiceError(ErrorKindInvalidCredentials, "account lookup missed", nil)
	passwordMismatch := NewServiceError(ErrorKindInvalidCredentials, "password hash mismatch", nil)
	locked := NewServiceError(ErrorKindLockedAccount, "account locked until later", nil)
	rateLimited := NewServiceError(ErrorKindPolicyDenied, "rate limit denied", nil)

	want := PublicErrorFor(accountLookup, PublicErrorContextLogin)
	for name, err := range map[string]error{
		"wrong username": accountLookup,
		"wrong password": passwordMismatch,
		"locked account": locked,
		"rate limited":   rateLimited,
	} {
		t.Run(name, func(t *testing.T) {
			got := PublicErrorFor(err, PublicErrorContextLogin)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("public error = %#v, want %#v", got, want)
			}
		})
	}
}

func TestOrchestratorLoginAppliesSharedPolicy(t *testing.T) {
	accountID, credentialID := mustAuthIDs(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	accounts := &loginAccountRepository{
		snapshot: AccountSnapshot{ID: accountID, Username: "Celeste"},
		state:    AccountState{AccountID: accountID},
	}
	rateLimiter := &loginRateLimiter{result: RateLimitResult{Allowed: true, Remaining: 4}}
	audit := &loginAuditWriter{}
	timing := &loginTiming{start: now}
	method := fakeAuthMethod{
		kind: account.CredentialKindPassword,
		verify: func(_ context.Context, req VerifyRequest) (AuthResult, error) {
			if req.AccountHint != accountID {
				t.Fatalf("account hint = %s, want %s", req.AccountHint, accountID)
			}
			if req.IP.String() != "203.0.113.10" {
				t.Fatalf("verify ip = %s, want 203.0.113.10", req.IP)
			}
			return AuthResult{
				AccountID:       accountID,
				CredentialID:    credentialID,
				VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPassword},
				MFAStatus:       MFAStatusNotRequired,
				Session:         SessionIssueInstructions{Issue: true},
			}, nil
		},
	}

	orchestrator, err := NewOrchestratorWithDeps(OrchestratorDeps{
		Accounts:          accounts,
		RateLimiter:       rateLimiter,
		Audit:             audit,
		DummyPasswordWork: &loginDummyPasswordWork{},
		Timing:            timing,
		Clock:             fakeClock{now: now},
	}, method)
	if err != nil {
		t.Fatalf("new orchestrator: %v", err)
	}

	result, err := orchestrator.Login(context.Background(), LoginRequest{
		Kind:            account.CredentialKindPassword,
		Username:        " CELESTE ",
		CredentialInput: "correct horse battery staple",
		IP:              "203.0.113.10",
		UserAgent:       "login-test",
		RequestID:       "req-login",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if result.AccountID != accountID || result.CredentialID != credentialID {
		t.Fatalf("login result = %#v", result)
	}
	if accounts.lookup.Username != "celeste" {
		t.Fatalf("lookup username = %q, want celeste", accounts.lookup.Username)
	}
	if len(rateLimiter.requests) != 1 {
		t.Fatalf("rate-limit calls = %d, want 1", len(rateLimiter.requests))
	}
	subject := rateLimiter.requests[0].Subject
	if subject.AccountID != accountID || subject.Username != "celeste" || subject.Endpoint != defaultLoginEndpoint {
		t.Fatalf("rate-limit subject = %#v", subject)
	}
	if !timing.waited {
		t.Fatal("login did not wait on timing equalizer")
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Type != AuditEventLoginSucceeded || event.AccountID != accountID || event.CredentialID != credentialID {
		t.Fatalf("audit event = %#v", event)
	}
	if event.Attributes["username_hash"] == "" || event.Attributes["username_hash"] == "celeste" {
		t.Fatalf("username hash should be populated without raw username: %#v", event.Attributes)
	}
}

func TestOrchestratorLoginRunsDummyPasswordWorkForMissingAccount(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	accounts := &loginAccountRepository{
		lookupErr: NewServiceError(ErrorKindInvalidCredentials, "account not found", nil),
	}
	rateLimiter := &loginRateLimiter{result: RateLimitResult{Allowed: true}}
	audit := &loginAuditWriter{}
	dummy := &loginDummyPasswordWork{}
	timing := &loginTiming{start: now}
	method := fakeAuthMethod{
		kind: account.CredentialKindPassword,
		verify: func(context.Context, VerifyRequest) (AuthResult, error) {
			t.Fatal("verify should not run for a missing account")
			return AuthResult{}, nil
		},
	}
	orchestrator, err := NewOrchestratorWithDeps(OrchestratorDeps{
		Accounts:          accounts,
		RateLimiter:       rateLimiter,
		Audit:             audit,
		DummyPasswordWork: dummy,
		Timing:            timing,
		Clock:             fakeClock{now: now},
	}, method)
	if err != nil {
		t.Fatalf("new orchestrator: %v", err)
	}

	_, err = orchestrator.Login(context.Background(), LoginRequest{
		Kind:            account.CredentialKindPassword,
		Username:        "missing",
		CredentialInput: "wrong password",
		IP:              "203.0.113.11",
		RequestID:       "req-missing",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login error = %v, want invalid credentials", err)
	}
	if !dummy.called || dummy.req.Username != "missing" {
		t.Fatalf("dummy password work = %#v", dummy)
	}
	if len(rateLimiter.requests) != 1 || !rateLimiter.requests[0].Subject.AccountID.IsZero() {
		t.Fatalf("rate-limit requests = %#v", rateLimiter.requests)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Type != AuditEventLoginFailed || event.Attributes["outcome"] != "invalid_credentials" {
		t.Fatalf("audit event = %#v", event)
	}
	if !timing.waited {
		t.Fatal("login failure did not wait on timing equalizer")
	}
}

func TestOrchestratorLoginNormalizesPolicyFailures(t *testing.T) {
	accountID, _ := mustAuthIDs(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		accounts   *loginAccountRepository
		limit      RateLimitResult
		methodErr  error
		wantReason string
	}{
		{
			name:       "rate limited",
			accounts:   &loginAccountRepository{snapshot: AccountSnapshot{ID: accountID}, state: AccountState{AccountID: accountID}},
			limit:      RateLimitResult{Allowed: false},
			wantReason: "rate_limited",
		},
		{
			name:       "locked account",
			accounts:   &loginAccountRepository{snapshot: AccountSnapshot{ID: accountID}, state: AccountState{AccountID: accountID, LockedUntil: now.Add(time.Minute)}},
			limit:      RateLimitResult{Allowed: true},
			wantReason: "locked_account",
		},
		{
			name:       "wrong password",
			accounts:   &loginAccountRepository{snapshot: AccountSnapshot{ID: accountID}, state: AccountState{AccountID: accountID}},
			limit:      RateLimitResult{Allowed: true},
			methodErr:  ErrInvalidCredentials,
			wantReason: "invalid_credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := &loginAuditWriter{}
			methodCalled := false
			method := fakeAuthMethod{
				kind: account.CredentialKindPassword,
				verify: func(context.Context, VerifyRequest) (AuthResult, error) {
					methodCalled = true
					return AuthResult{}, tt.methodErr
				},
			}
			orchestrator, err := NewOrchestratorWithDeps(OrchestratorDeps{
				Accounts:          tt.accounts,
				RateLimiter:       &loginRateLimiter{result: tt.limit},
				Audit:             audit,
				DummyPasswordWork: &loginDummyPasswordWork{},
				Timing:            &loginTiming{start: now},
				Clock:             fakeClock{now: now},
			}, method)
			if err != nil {
				t.Fatalf("new orchestrator: %v", err)
			}

			_, err = orchestrator.Login(context.Background(), LoginRequest{
				Kind:            account.CredentialKindPassword,
				Username:        "celeste",
				CredentialInput: "wrong password",
				IP:              "203.0.113.12",
			})
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("login error = %v, want invalid credentials", err)
			}
			if tt.methodErr == nil && methodCalled {
				t.Fatal("method should not run before rate or lockout rejection")
			}
			if len(audit.events) != 1 || audit.events[0].Attributes["outcome"] != tt.wantReason {
				t.Fatalf("audit events = %#v, want reason %q", audit.events, tt.wantReason)
			}
		})
	}
}

func TestClockAndRandomFakesMakeChallengeExpiryDeterministic(t *testing.T) {
	accountID, credentialID := mustAuthIDs(t)
	clock := &steppingClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	random := fakeRandomReader{data: []byte{0xde, 0xad, 0xbe, 0xef}}
	method := &challengeMethod{
		accountID:    accountID,
		credentialID: credentialID,
		clock:        clock,
		random:       random,
		ttl:          time.Minute,
	}
	orchestrator, err := NewOrchestrator(method)
	if err != nil {
		t.Fatalf("new orchestrator: %v", err)
	}

	begin, err := orchestrator.Begin(context.Background(), account.CredentialKindWebAuthn, BeginRequest{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if begin.ChallengeID != "deadbeef" {
		t.Fatalf("challenge ID = %q, want deadbeef", begin.ChallengeID)
	}
	if !begin.ExpiresAt.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("expires at = %v, want %v", begin.ExpiresAt, clock.Now().Add(time.Minute))
	}

	if _, err := orchestrator.Verify(context.Background(), account.CredentialKindWebAuthn, VerifyRequest{ChallengeID: begin.ChallengeID}); err != nil {
		t.Fatalf("verify before expiry: %v", err)
	}

	clock.Advance(time.Minute)
	if _, err := orchestrator.Verify(context.Background(), account.CredentialKindWebAuthn, VerifyRequest{ChallengeID: begin.ChallengeID}); !errors.Is(err, ErrExpiredChallenge) {
		t.Fatalf("verify at expiry error = %v, want expired challenge", err)
	}
}

type challengeMethod struct {
	accountID    account.AccountID
	credentialID account.CredentialID
	clock        Clock
	random       RandomReader
	ttl          time.Duration
	challenge    BeginResult
}

var _ AuthMethod = (*challengeMethod)(nil)

func (m *challengeMethod) Kind() account.CredentialKind {
	return account.CredentialKindWebAuthn
}

func (m *challengeMethod) Begin(context.Context, BeginRequest) (BeginResult, error) {
	buf := make([]byte, 4)
	if _, err := m.random.Read(buf); err != nil {
		return BeginResult{}, err
	}
	m.challenge = BeginResult{
		ChallengeID: hex.EncodeToString(buf),
		ExpiresAt:   m.clock.Now().Add(m.ttl),
	}
	return m.challenge, nil
}

func (m *challengeMethod) Verify(_ context.Context, req VerifyRequest) (AuthResult, error) {
	if req.ChallengeID != m.challenge.ChallengeID {
		return AuthResult{}, ErrInvalidCredentials
	}
	if !m.clock.Now().Before(m.challenge.ExpiresAt) {
		return AuthResult{}, ErrExpiredChallenge
	}
	return AuthResult{
		AccountID:       m.accountID,
		CredentialID:    m.credentialID,
		VerifiedFactors: []account.FactorKind{account.FactorKindUser, account.FactorKindPasskey},
		MFAStatus:       MFAStatusNotRequired,
		Session:         SessionIssueInstructions{Issue: true},
	}, nil
}

type steppingClock struct {
	now time.Time
}

var _ Clock = (*steppingClock)(nil)

func (c *steppingClock) Now() time.Time {
	return c.now
}

func (c *steppingClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

type loginAccountRepository struct {
	snapshot  AccountSnapshot
	state     AccountState
	lookup    AccountLookup
	lookupErr error
	stateErr  error
}

var _ AccountRepository = (*loginAccountRepository)(nil)

func (r *loginAccountRepository) LookupAccount(_ context.Context, lookup AccountLookup) (AccountSnapshot, error) {
	r.lookup = lookup
	if r.lookupErr != nil {
		return AccountSnapshot{}, r.lookupErr
	}
	return r.snapshot, nil
}

func (r *loginAccountRepository) AccountState(context.Context, account.AccountID) (AccountState, error) {
	if r.stateErr != nil {
		return AccountState{}, r.stateErr
	}
	return r.state, nil
}

type loginRateLimiter struct {
	result   RateLimitResult
	err      error
	requests []RateLimitRequest
}

var _ RateLimiter = (*loginRateLimiter)(nil)

func (l *loginRateLimiter) CheckRateLimit(_ context.Context, req RateLimitRequest) (RateLimitResult, error) {
	l.requests = append(l.requests, req)
	if l.err != nil {
		return RateLimitResult{}, l.err
	}
	return l.result, nil
}

type loginAuditWriter struct {
	events []AuditEvent
	err    error
}

var _ AuditWriter = (*loginAuditWriter)(nil)

func (w *loginAuditWriter) WriteAuditEvent(_ context.Context, event AuditEvent) error {
	w.events = append(w.events, event)
	return w.err
}

type loginDummyPasswordWork struct {
	called bool
	req    DummyPasswordWorkRequest
	err    error
}

var _ DummyPasswordWork = (*loginDummyPasswordWork)(nil)

func (w *loginDummyPasswordWork) RunDummyPasswordWork(_ context.Context, req DummyPasswordWorkRequest) error {
	w.called = true
	w.req = req
	return w.err
}

type loginTiming struct {
	start  time.Time
	waited bool
	err    error
}

var _ TimingEqualizer = (*loginTiming)(nil)

func (t *loginTiming) Started() time.Time {
	return t.start
}

func (t *loginTiming) Wait(context.Context, time.Time) error {
	t.waited = true
	return t.err
}
