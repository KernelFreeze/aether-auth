package webauthn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/webauthn/webauthntest"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestRegistrationServiceStoresChallengeAndPersistsCredential(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	sessionID := mustWebAuthnSessionID(t, "018f1f74-10a1-7000-9000-000000008201")
	credentialID := mustRegistrationCredentialID(t, "018f1f74-10a1-7000-9000-000000008202")
	user := webAuthnTestUser(t)
	server := newTestServer(t)
	client := webauthntest.NewClient(defaultRelyingPartyName, "localhost", "https://localhost")
	client.SetUserHandle(user.WebAuthnID())
	credentials := &registrationCredentialStore{}
	challenges := &registrationChallengeStore{}
	clock := testutil.NewFakeClock(now)
	service := NewRegistrationService(RegistrationServiceDeps{
		Server:      server,
		Credentials: credentials,
		Challenges:  challenges,
		IDs:         registrationIDs{credentialID: credentialID, challengeID: "challenge-id-1"},
		Clock:       clock,
	})

	begin, err := service.BeginRegistration(ctx, RegistrationStartRequest{
		AccountID:               user.AccountID,
		SessionID:               sessionID,
		Username:                user.Username,
		DisplayName:             user.DisplayName,
		RequestID:               "request-id",
		UserVerification:        UserVerificationDiscouraged,
		AuthenticatorAttachment: AuthenticatorAttachmentPlatform,
	})
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	if begin.ChallengeID != "challenge-id-1" || len(begin.Options) == 0 || begin.ExpiresAt.IsZero() {
		t.Fatalf("begin result = %#v", begin)
	}
	stored := challenges.saved["challenge-id-1"]
	if stored.Purpose != auth.ChallengePurposeWebAuthn || stored.Provider != registrationChallengeProvider || stored.SessionBinding != sessionID.String() || stored.RequestID != "request-id" {
		t.Fatalf("stored challenge = %#v", stored)
	}

	attestation, err := client.CreateAttestationResponse(begin.Options)
	if err != nil {
		t.Fatalf("create attestation: %v", err)
	}
	clock.Advance(time.Second)
	credential, err := service.FinishRegistration(ctx, RegistrationCompleteRequest{
		AccountID:           user.AccountID,
		SessionID:           sessionID,
		Username:            user.Username,
		DisplayName:         user.DisplayName,
		ChallengeID:         begin.ChallengeID,
		CredentialName:      "laptop passkey",
		AttestationResponse: attestation,
	})
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	if credential.ID != credentialID || credential.AccountID != user.AccountID || credential.DisplayName != "laptop passkey" || !credential.Verified {
		t.Fatalf("credential = %#v", credential)
	}
	if credentials.created.ID != credentialID || len(credentials.created.KeyID) == 0 || len(credentials.created.PublicKey) == 0 {
		t.Fatalf("created credential = %#v", credentials.created)
	}

	_, err = service.FinishRegistration(ctx, RegistrationCompleteRequest{
		AccountID:           user.AccountID,
		SessionID:           sessionID,
		Username:            user.Username,
		DisplayName:         user.DisplayName,
		ChallengeID:         begin.ChallengeID,
		CredentialName:      "replay",
		AttestationResponse: attestation,
	})
	if !errors.Is(err, auth.ErrReplayedChallenge) {
		t.Fatalf("replayed finish error = %v, want replayed challenge", err)
	}
}

type registrationCredentialStore struct {
	existing []Credential
	created  Credential
}

func (s *registrationCredentialStore) CreateCredential(_ context.Context, credential Credential) (Credential, error) {
	s.created = credential
	return credential, nil
}

func (s *registrationCredentialStore) GetCredentialByKeyID(context.Context, []byte) (Credential, error) {
	return Credential{}, auth.ErrInvalidCredentials
}

func (s *registrationCredentialStore) ListCredentials(context.Context, account.AccountID, string) ([]Credential, error) {
	return append([]Credential(nil), s.existing...), nil
}

func (s *registrationCredentialStore) UpdateCredentialAssertion(context.Context, Credential) (Credential, error) {
	return Credential{}, nil
}

type registrationChallengeStore struct {
	saved map[string]auth.StoredChallenge
	used  map[string]bool
}

func (s *registrationChallengeStore) SaveChallenge(_ context.Context, challenge auth.StoredChallenge) error {
	if s.saved == nil {
		s.saved = map[string]auth.StoredChallenge{}
	}
	s.saved[challenge.ID] = challenge
	return nil
}

func (s *registrationChallengeStore) ConsumeChallenge(_ context.Context, lookup auth.ChallengeLookup) (auth.StoredChallenge, error) {
	if s.used == nil {
		s.used = map[string]bool{}
	}
	if s.used[lookup.ID] {
		return auth.StoredChallenge{}, auth.ErrReplayedChallenge
	}
	challenge, ok := s.saved[lookup.ID]
	if !ok {
		return auth.StoredChallenge{}, auth.ErrInvalidCredentials
	}
	if challenge.Purpose != lookup.Purpose || challenge.SessionBinding != lookup.SessionBinding || challenge.Provider != lookup.Provider {
		return auth.StoredChallenge{}, auth.ErrInvalidCredentials
	}
	s.used[lookup.ID] = true
	return challenge, nil
}

func (s *registrationChallengeStore) DeleteExpiredChallenges(context.Context, time.Time) error {
	return nil
}

type registrationIDs struct {
	credentialID account.CredentialID
	challengeID  string
}

func (ids registrationIDs) NewCredentialID() (account.CredentialID, error) {
	return ids.credentialID, nil
}

func (ids registrationIDs) NewChallengeID() (string, error) {
	return ids.challengeID, nil
}

func mustRegistrationCredentialID(t testing.TB, value string) account.CredentialID {
	t.Helper()
	id, err := account.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("parse credential id: %v", err)
	}
	return id
}

func mustWebAuthnSessionID(t testing.TB, value string) account.SessionID {
	t.Helper()
	id, err := account.ParseSessionID(value)
	if err != nil {
		t.Fatalf("parse session id: %v", err)
	}
	return id
}
