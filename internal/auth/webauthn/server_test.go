package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/webauthn/webauthntest"
)

func TestServerCompletesRegistrationAndAssertion(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
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
	if len(registration.Options) == 0 || registration.Challenge.Challenge == "" {
		t.Fatalf("registration result = %#v", registration)
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
	if !credential.Verified || credential.RelyingPartyID != "localhost" || len(credential.KeyID) == 0 || len(credential.PublicKey) == 0 {
		t.Fatalf("credential = %#v", credential)
	}
	if credential.DisplayName != "laptop passkey" || credential.CreatedAt != now {
		t.Fatalf("credential metadata = %#v", credential)
	}

	client.SetSignCount(1)
	user.Credentials = []Credential{credential}
	login, err := server.BeginLogin(ctx, LoginBeginRequest{
		User:             user,
		UserVerification: UserVerificationDiscouraged,
	})
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertion, err := client.CreateAssertionResponse(login.Options, false)
	if err != nil {
		t.Fatalf("create assertion: %v", err)
	}
	result, err := server.FinishLogin(ctx, LoginFinishRequest{
		User:              user,
		Challenge:         login.Challenge,
		AssertionResponse: assertion,
		Now:               now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("finish login: %v", err)
	}
	if result.Credential.SignCount != 1 || result.Credential.LastUsedAt != now.Add(time.Minute) {
		t.Fatalf("assertion credential = %#v", result.Credential)
	}
	if !result.FactorCheck.Verified() || result.FactorCheck.Kind != account.FactorKindPasskey {
		t.Fatalf("factor check = %#v", result.FactorCheck)
	}
}

func TestServerRejectsMismatchedChallenge(t *testing.T) {
	ctx := context.Background()
	server := newTestServer(t)
	user := webAuthnTestUser(t)
	client := webauthntest.NewClient(defaultRelyingPartyName, "localhost", "https://localhost")
	client.SetUserHandle(user.WebAuthnID())

	registration, err := server.BeginRegistration(ctx, RegistrationBeginRequest{User: user})
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
		AttestationResponse: attestation,
	})
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}

	user.Credentials = []Credential{credential}
	login, err := server.BeginLogin(ctx, LoginBeginRequest{User: user})
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertion, err := client.CreateAssertionResponse(login.Options, false)
	if err != nil {
		t.Fatalf("create assertion: %v", err)
	}
	login.Challenge.Challenge = "wrong-challenge"

	_, err = server.FinishLogin(ctx, LoginFinishRequest{
		User:              user,
		Challenge:         login.Challenge,
		AssertionResponse: assertion,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("finish login error = %v, want invalid credentials", err)
	}
}

func TestServerRejectsReplayedAssertionBySignCount(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	server := newTestServer(t)
	user := webAuthnTestUser(t)
	client := webauthntest.NewClient(defaultRelyingPartyName, "localhost", "https://localhost")
	client.SetUserHandle(user.WebAuthnID())

	registration, err := server.BeginRegistration(ctx, RegistrationBeginRequest{User: user})
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
		AttestationResponse: attestation,
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}

	client.SetSignCount(1)
	user.Credentials = []Credential{credential}
	login, err := server.BeginLogin(ctx, LoginBeginRequest{User: user})
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	assertion, err := client.CreateAssertionResponse(login.Options, false)
	if err != nil {
		t.Fatalf("create assertion: %v", err)
	}
	first, err := server.FinishLogin(ctx, LoginFinishRequest{
		User:              user,
		Challenge:         login.Challenge,
		AssertionResponse: assertion,
		Now:               now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("finish first login: %v", err)
	}

	user.Credentials = []Credential{first.Credential}
	replayed, err := server.FinishLogin(ctx, LoginFinishRequest{
		User:              user,
		Challenge:         login.Challenge,
		AssertionResponse: assertion,
		Now:               now.Add(2 * time.Minute),
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("finish replayed login error = %v, want invalid credentials", err)
	}
	if !replayed.CloneWarning {
		t.Fatalf("replayed result = %#v, want clone warning", replayed)
	}
}

func TestCredentialsForRelyingPartyFiltersUnsafeCredentials(t *testing.T) {
	accountID := mustWebAuthnAccountID(t, "018f1f74-10a1-7000-9000-000000008001")
	credentials := []Credential{
		{AccountID: accountID, KeyID: []byte("ready"), PublicKey: []byte("key"), RelyingPartyID: "localhost", Verified: true, AttestationType: "packed"},
		{AccountID: accountID, KeyID: []byte("wrong-rp"), PublicKey: []byte("key"), RelyingPartyID: "example.com", Verified: true},
		{AccountID: accountID, KeyID: []byte("unverified"), PublicKey: []byte("key"), RelyingPartyID: "localhost"},
		{AccountID: accountID, PublicKey: []byte("key"), RelyingPartyID: "localhost", Verified: true},
	}

	got := CredentialsForRelyingParty(credentials, "localhost")
	if len(got) != 1 || string(got[0].ID) != "ready" || got[0].AttestationType != "packed" {
		t.Fatalf("credentials = %#v", got)
	}
}

func TestBeginRegistrationExcludesExistingCredentials(t *testing.T) {
	ctx := context.Background()
	server := newTestServer(t)
	user := webAuthnTestUser(t)
	user.Credentials = []Credential{{
		AccountID:       user.AccountID,
		KeyID:           []byte("existing-key"),
		PublicKey:       []byte("existing-public-key"),
		AttestationType: "packed",
		RelyingPartyID:  "localhost",
		Verified:        true,
	}}

	registration, err := server.BeginRegistration(ctx, RegistrationBeginRequest{User: user})
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	var payload struct {
		PublicKey struct {
			ExcludeCredentials []struct {
				Type string                    `json:"type"`
				ID   protocol.URLEncodedBase64 `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(registration.Options, &payload); err != nil {
		t.Fatalf("unmarshal options: %v", err)
	}
	if len(payload.PublicKey.ExcludeCredentials) != 1 || string(payload.PublicKey.ExcludeCredentials[0].ID) != "existing-key" {
		t.Fatalf("exclude credentials = %#v", payload.PublicKey.ExcludeCredentials)
	}
}

func newTestServer(t testing.TB) *Server {
	t.Helper()
	server, err := New(Config{
		RelyingPartyID:      "localhost",
		RelyingPartyName:    defaultRelyingPartyName,
		RelyingPartyOrigins: []string{"https://localhost"},
		UserVerification:    UserVerificationDiscouraged,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func webAuthnTestUser(t testing.TB) User {
	t.Helper()
	return User{
		AccountID:   mustWebAuthnAccountID(t, "018f1f74-10a1-7000-9000-000000008000"),
		Username:    "celeste",
		DisplayName: "Celeste",
	}
}

func mustWebAuthnAccountID(t testing.TB, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}
