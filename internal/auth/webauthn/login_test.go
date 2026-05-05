package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/webauthn/webauthntest"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestLoginServiceStoresChallengeAndUpdatesCredential(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	user, credential, client := registeredPasskeyCredential(t, now)
	credential.ID = mustRegistrationCredentialID(t, "018f1f74-10a1-7000-9000-000000008302")
	client.SetSignCount(1)

	credentials := &loginCredentialStore{credentials: []Credential{credential}}
	challenges := &registrationChallengeStore{}
	clock := testutil.NewFakeClock(now)
	service := NewLoginService(LoginServiceDeps{
		Server:      newTestServer(t),
		Credentials: credentials,
		Challenges:  challenges,
		IDs:         &loginIDs{challengeIDs: []string{"login-challenge-1"}},
		Clock:       clock,
	})

	begin, err := service.BeginLogin(ctx, LoginStartRequest{
		AccountID:        user.AccountID,
		Username:         user.Username,
		DisplayName:      user.DisplayName,
		RequestID:        "request-id",
		UserVerification: UserVerificationDiscouraged,
	})
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	if begin.ChallengeID != "login-challenge-1" || len(begin.Options) == 0 || begin.ExpiresAt.IsZero() {
		t.Fatalf("begin result = %#v", begin)
	}
	stored := challenges.saved["login-challenge-1"]
	if stored.Purpose != auth.ChallengePurposeWebAuthn || stored.Provider != loginChallengeProvider || stored.RequestID != "request-id" {
		t.Fatalf("stored challenge = %#v", stored)
	}

	assertion, err := client.CreateAssertionResponse(begin.Options, false)
	if err != nil {
		t.Fatalf("create assertion: %v", err)
	}
	clock.Advance(time.Second)
	result, err := service.FinishLogin(ctx, LoginCompleteRequest{
		AccountID:         user.AccountID,
		Username:          user.Username,
		DisplayName:       user.DisplayName,
		ChallengeID:       begin.ChallengeID,
		AssertionResponse: assertion,
	})
	if err != nil {
		t.Fatalf("finish login: %v", err)
	}
	if result.Credential.ID != credential.ID || result.Credential.SignCount != 1 || result.Credential.LastUsedAt != now.Add(time.Second) {
		t.Fatalf("assertion credential = %#v", result.Credential)
	}
	if !result.FactorCheck.Verified() || result.FactorCheck.Kind != account.FactorKindPasskey {
		t.Fatalf("factor check = %#v", result.FactorCheck)
	}
	if len(credentials.updates) != 1 || credentials.updates[0].ID != credential.ID {
		t.Fatalf("credential updates = %#v", credentials.updates)
	}

	_, err = service.FinishLogin(ctx, LoginCompleteRequest{
		AccountID:         user.AccountID,
		Username:          user.Username,
		DisplayName:       user.DisplayName,
		ChallengeID:       begin.ChallengeID,
		AssertionResponse: assertion,
	})
	if !errors.Is(err, auth.ErrReplayedChallenge) {
		t.Fatalf("replayed finish error = %v, want replayed challenge", err)
	}
}

func TestLoginServiceWritesCloneWarningAudit(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	user, credential, client := registeredPasskeyCredential(t, now)
	credential.ID = mustRegistrationCredentialID(t, "018f1f74-10a1-7000-9000-000000008312")
	client.SetSignCount(1)

	credentials := &loginCredentialStore{credentials: []Credential{credential}}
	audit := &loginAuditWriter{}
	service := NewLoginService(LoginServiceDeps{
		Server:      newTestServer(t),
		Credentials: credentials,
		Challenges:  &registrationChallengeStore{},
		Audit:       audit,
		IDs:         &loginIDs{challengeIDs: []string{"login-challenge-1", "login-challenge-2"}},
		Clock:       testutil.NewFakeClock(now),
	})

	first := finishLoginWithService(t, ctx, service, user, client, "req-first")
	if first.Credential.SignCount != 1 {
		t.Fatalf("first credential = %#v", first.Credential)
	}
	second, err := service.BeginLogin(ctx, LoginStartRequest{
		AccountID:        user.AccountID,
		Username:         user.Username,
		DisplayName:      user.DisplayName,
		UserVerification: UserVerificationDiscouraged,
	})
	if err != nil {
		t.Fatalf("begin second login: %v", err)
	}
	replayedCountAssertion, err := client.CreateAssertionResponse(second.Options, false)
	if err != nil {
		t.Fatalf("create replayed-count assertion: %v", err)
	}

	_, err = service.FinishLogin(ctx, LoginCompleteRequest{
		AccountID:         user.AccountID,
		Username:          user.Username,
		DisplayName:       user.DisplayName,
		ChallengeID:       second.ChallengeID,
		AssertionResponse: replayedCountAssertion,
		RequestID:         "req-clone",
		IP:                "2001:db8::1",
		UserAgent:         "webauthn-test",
		Now:               now.Add(10 * time.Second),
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("clone warning error = %v, want invalid credentials", err)
	}
	if len(credentials.updates) != 1 {
		t.Fatalf("credential updates = %d, want only the successful assertion update", len(credentials.updates))
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Type != auth.AuditEventWebAuthnCloneWarning || event.AccountID != user.AccountID || event.CredentialID != credential.ID {
		t.Fatalf("audit event = %#v", event)
	}
	if event.RequestID != "req-clone" || event.IP != "2001:db8::1" || event.UserAgent != "webauthn-test" {
		t.Fatalf("audit request context = %#v", event)
	}
	if event.Attributes["outcome"] != "clone_warning" || event.Attributes["method"] != account.CredentialKindWebAuthn.String() {
		t.Fatalf("audit attributes = %#v", event.Attributes)
	}
}

func finishLoginWithService(t testing.TB, ctx context.Context, service *LoginService, user User, client *webauthntest.Client, requestID string) AssertionResult {
	t.Helper()
	begin, err := service.BeginLogin(ctx, LoginStartRequest{
		AccountID:        user.AccountID,
		Username:         user.Username,
		DisplayName:      user.DisplayName,
		RequestID:        requestID,
		UserVerification: UserVerificationDiscouraged,
	})
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertion, err := client.CreateAssertionResponse(begin.Options, false)
	if err != nil {
		t.Fatalf("create assertion: %v", err)
	}
	result, err := service.FinishLogin(ctx, LoginCompleteRequest{
		AccountID:         user.AccountID,
		Username:          user.Username,
		DisplayName:       user.DisplayName,
		ChallengeID:       begin.ChallengeID,
		AssertionResponse: assertion,
		RequestID:         requestID,
	})
	if err != nil {
		t.Fatalf("finish login: %v", err)
	}
	return result
}

func registeredPasskeyCredential(t testing.TB, now time.Time) (User, Credential, *webauthntest.Client) {
	t.Helper()
	ctx := context.Background()
	server := newTestServer(t)
	user := webAuthnTestUser(t)
	client := webauthntest.NewClient(defaultRelyingPartyName, "localhost", "https://localhost")
	client.SetUserHandle(user.WebAuthnID())

	registration, err := server.BeginRegistration(ctx, RegistrationBeginRequest{
		User:                    user,
		UserVerification:        UserVerificationDiscouraged,
		AuthenticatorAttachment: AuthenticatorAttachmentPlatform,
	})
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	attestation, err := client.CreateAttestationResponse(registration.Options)
	if err != nil {
		t.Fatalf("create attestation: %v", err)
	}
	credential, err := server.FinishRegistration(ctx, RegistrationFinishRequest{
		User:                user,
		Challenge:           registration.Challenge,
		CredentialName:      "laptop passkey",
		AttestationResponse: attestation,
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	return user, credential, client
}

type loginCredentialStore struct {
	credentials []Credential
	updates     []Credential
}

func (s *loginCredentialStore) CreateCredential(_ context.Context, credential Credential) (Credential, error) {
	s.credentials = append(s.credentials, credential)
	return credential, nil
}

func (s *loginCredentialStore) GetCredentialByKeyID(_ context.Context, keyID []byte) (Credential, error) {
	for _, credential := range s.credentials {
		if bytes.Equal(credential.KeyID, keyID) {
			return credential, nil
		}
	}
	return Credential{}, auth.ErrInvalidCredentials
}

func (s *loginCredentialStore) ListCredentials(_ context.Context, accountID account.AccountID, relyingPartyID string) ([]Credential, error) {
	credentials := make([]Credential, 0, len(s.credentials))
	for _, credential := range s.credentials {
		if credential.AccountID != accountID {
			continue
		}
		if relyingPartyID != "" && credential.RelyingPartyID != relyingPartyID {
			continue
		}
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

func (s *loginCredentialStore) UpdateCredentialAssertion(_ context.Context, credential Credential) (Credential, error) {
	s.updates = append(s.updates, credential)
	for i := range s.credentials {
		if s.credentials[i].ID == credential.ID {
			s.credentials[i] = credential
			return credential, nil
		}
	}
	return Credential{}, auth.ErrInvalidCredentials
}

type loginIDs struct {
	challengeIDs []string
	next         int
}

func (ids *loginIDs) NewChallengeID() (string, error) {
	if ids == nil || ids.next >= len(ids.challengeIDs) {
		return "", errors.New("no challenge ids left")
	}
	id := ids.challengeIDs[ids.next]
	ids.next++
	return id, nil
}

type loginAuditWriter struct {
	events []auth.AuditEvent
}

func (w *loginAuditWriter) WriteAuditEvent(_ context.Context, event auth.AuditEvent) error {
	w.events = append(w.events, event)
	return nil
}
