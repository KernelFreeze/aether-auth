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

	want := PublicErrorFor(accountLookup, PublicErrorContextLogin)
	for name, err := range map[string]error{
		"wrong username": accountLookup,
		"wrong password": passwordMismatch,
		"locked account": locked,
	} {
		t.Run(name, func(t *testing.T) {
			got := PublicErrorFor(err, PublicErrorContextLogin)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("public error = %#v, want %#v", got, want)
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
