package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCredentialServiceCreatesOIDCCredentialWithEncryptedPayload(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000301")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000302")
	store := &fakeCredentialStore{}
	box := &fakeCredentialPayloadBox{}
	service := NewCredentialService(CredentialDeps{
		Store: store,
		Box:   box,
		IDs:   fakeCredentialIDs{credentialID: credentialID},
		Clock: fakeCredentialClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})

	got, err := service.CreateCredential(ctx, CreateCredentialRequest{
		AccountID:       accountID,
		Kind:            CredentialKindOIDC,
		Provider:        "  GitHub  ",
		ExternalSubject: "  sub-123  ",
		DisplayName:     " GitHub ",
		Verified:        true,
		Payload:         map[string]string{"email": "user@example.com"},
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	if got.ID != credentialID || got.AccountID != accountID || got.Provider != "github" || got.ExternalSubject != "sub-123" {
		t.Fatalf("credential = %#v", got)
	}
	if !got.Verified || got.DisplayName != "GitHub" {
		t.Fatalf("credential metadata = %#v", got)
	}
	if store.providerChecked != "github" || store.subjectChecked != "sub-123" {
		t.Fatalf("provider uniqueness check = %q/%q", store.providerChecked, store.subjectChecked)
	}
	if store.draft.ID != credentialID || store.draft.Kind != CredentialKindOIDC {
		t.Fatalf("store draft = %#v", store.draft)
	}
	if !bytes.HasPrefix(store.draft.Payload.Ciphertext, []byte("sealed:")) {
		t.Fatalf("ciphertext = %q, want sealed payload", store.draft.Payload.Ciphertext)
	}

	var plaintext map[string]string
	if err := json.Unmarshal(box.sealReq.Plaintext, &plaintext); err != nil {
		t.Fatalf("decode sealed plaintext: %v", err)
	}
	if plaintext["email"] != "user@example.com" {
		t.Fatalf("plaintext = %#v", plaintext)
	}

	var aad map[string]string
	if err := json.Unmarshal(box.sealReq.AssociatedData, &aad); err != nil {
		t.Fatalf("decode aad: %v", err)
	}
	if aad["account_id"] != accountID.String() || aad["credential_id"] != credentialID.String() || aad["kind"] != "oidc" || aad["provider"] != "github" {
		t.Fatalf("aad = %#v", aad)
	}
}

func TestCredentialServiceRejectsDuplicateOIDCSubject(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000303")
	store := &fakeCredentialStore{providerSubjectExists: true}
	service := NewCredentialService(CredentialDeps{
		Store: store,
		Box:   &fakeCredentialPayloadBox{},
		IDs:   fakeCredentialIDs{credentialID: mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000304")},
		Clock: fakeCredentialClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})

	_, err := service.CreateCredential(ctx, CreateCredentialRequest{
		AccountID:       accountID,
		Kind:            CredentialKindOIDC,
		Provider:        "github",
		ExternalSubject: "sub-123",
		Payload:         map[string]string{"email": "user@example.com"},
	})
	if !errors.Is(err, ErrCredentialAlreadyExists) {
		t.Fatalf("create error = %v, want ErrCredentialAlreadyExists", err)
	}
	if store.createCalled {
		t.Fatal("duplicate provider subject should not create a credential")
	}
}

func TestCredentialServiceRemoveRequiresRecentReauthentication(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000305")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000306")
	store := &fakeCredentialStore{}
	service := NewCredentialService(CredentialDeps{
		Store: store,
		Box:   &fakeCredentialPayloadBox{},
		IDs:   fakeCredentialIDs{credentialID: credentialID},
		Clock: fakeCredentialClock{now: now},
	})

	for _, reauthenticatedAt := range []time.Time{time.Time{}, now.Add(-6 * time.Minute), now.Add(time.Second)} {
		_, err := service.RemoveCredential(ctx, RemoveCredentialRequest{
			AccountID:         accountID,
			CredentialID:      credentialID,
			ReauthenticatedAt: reauthenticatedAt,
		})
		if !errors.Is(err, ErrCredentialReauthenticationRequired) {
			t.Fatalf("remove error = %v, want ErrCredentialReauthenticationRequired", err)
		}
	}
	if store.removeCalled {
		t.Fatal("remove should not reach the store without recent reauthentication")
	}
}

func TestCredentialServiceRemoveProtectsLastCredential(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000307")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000308")
	service := NewCredentialService(CredentialDeps{
		Store: &fakeCredentialStore{removeErr: ErrLastCredential},
		Box:   &fakeCredentialPayloadBox{},
		IDs:   fakeCredentialIDs{credentialID: credentialID},
		Clock: fakeCredentialClock{now: now},
	})

	_, err := service.RemoveCredential(ctx, RemoveCredentialRequest{
		AccountID:         accountID,
		CredentialID:      credentialID,
		ReauthenticatedAt: now.Add(-time.Minute),
	})
	if !errors.Is(err, ErrLastCredential) {
		t.Fatalf("remove error = %v, want ErrLastCredential", err)
	}
}

func TestCredentialServiceReadsDecryptedPayloadJSON(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000309")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000310")
	payload := CredentialPayload{
		Algorithm:  credentialPayloadAlgorithm,
		KeyRef:     "env://AUTH_AES_KEY",
		Nonce:      []byte("nonce"),
		Ciphertext: []byte("ciphertext"),
		AAD:        []byte(`{"kind":"password"}`),
		Version:    credentialPayloadVersion,
	}
	store := &fakeCredentialStore{
		credential: Credential{
			ID:        credentialID,
			AccountID: accountID,
			Kind:      CredentialKindPassword,
			Verified:  true,
			Payload:   payload,
		},
	}
	box := &fakeCredentialPayloadBox{openPlaintext: []byte(`{"phc":"$argon2id$..."}`)}
	service := NewCredentialService(CredentialDeps{
		Store: store,
		Box:   box,
		IDs:   fakeCredentialIDs{credentialID: credentialID},
		Clock: fakeCredentialClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})

	got, err := service.ReadCredential(ctx, accountID, credentialID)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	if got.ID != credentialID || string(got.PayloadJSON) != `{"phc":"$argon2id$..."}` {
		t.Fatalf("read credential = %#v", got)
	}
	if !bytes.Equal(box.openReq.AssociatedData, payload.AAD) {
		t.Fatalf("open aad = %q, want %q", box.openReq.AssociatedData, payload.AAD)
	}
}

type fakeCredentialStore struct {
	providerSubjectExists bool
	providerChecked       string
	subjectChecked        string
	createCalled          bool
	removeCalled          bool
	removeErr             error
	draft                 CredentialDraft
	credential            Credential
}

func (s *fakeCredentialStore) ProviderSubjectExists(_ context.Context, provider, externalSubject string) (bool, error) {
	s.providerChecked = provider
	s.subjectChecked = externalSubject
	return s.providerSubjectExists, nil
}

func (s *fakeCredentialStore) CreateCredential(_ context.Context, draft CredentialDraft) (Credential, error) {
	s.createCalled = true
	s.draft = draft
	return Credential{
		ID:              draft.ID,
		AccountID:       draft.AccountID,
		Kind:            draft.Kind,
		Provider:        draft.Provider,
		ExternalSubject: draft.ExternalSubject,
		DisplayName:     draft.DisplayName,
		Verified:        draft.Verified,
		Payload:         draft.Payload,
	}, nil
}

func (s *fakeCredentialStore) GetCredential(_ context.Context, _ AccountID, _ CredentialID) (Credential, error) {
	return s.credential, nil
}

func (s *fakeCredentialStore) ListCredentials(context.Context, AccountID) ([]Credential, error) {
	return nil, nil
}

func (s *fakeCredentialStore) UpdateCredential(context.Context, CredentialUpdate) (Credential, error) {
	return s.credential, nil
}

func (s *fakeCredentialStore) RemoveCredential(_ context.Context, accountID AccountID, credentialID CredentialID, revokedAt time.Time) (Credential, error) {
	s.removeCalled = true
	if s.removeErr != nil {
		return Credential{}, s.removeErr
	}
	return Credential{
		ID:        credentialID,
		AccountID: accountID,
		RevokedAt: revokedAt,
	}, nil
}

type fakeCredentialPayloadBox struct {
	sealReq       CredentialPayloadSealRequest
	openReq       CredentialPayloadOpenRequest
	openPlaintext []byte
}

func (b *fakeCredentialPayloadBox) SealCredentialPayload(_ context.Context, req CredentialPayloadSealRequest) (CredentialPayload, error) {
	b.sealReq = req
	return CredentialPayload{
		Algorithm:  credentialPayloadAlgorithm,
		KeyRef:     "env://AUTH_AES_KEY",
		Nonce:      []byte("nonce"),
		Ciphertext: append([]byte("sealed:"), req.Plaintext...),
		Version:    credentialPayloadVersion,
	}, nil
}

func (b *fakeCredentialPayloadBox) OpenCredentialPayload(_ context.Context, req CredentialPayloadOpenRequest) ([]byte, error) {
	b.openReq = req
	return append([]byte(nil), b.openPlaintext...), nil
}

type fakeCredentialIDs struct {
	credentialID CredentialID
}

func (g fakeCredentialIDs) NewCredentialID() (CredentialID, error) {
	return g.credentialID, nil
}

type fakeCredentialClock struct {
	now time.Time
}

func (c fakeCredentialClock) Now() time.Time {
	return c.now
}

func mustCredentialAccountID(t testing.TB, value string) AccountID {
	t.Helper()
	id, err := ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func mustCredentialCredentialID(t testing.TB, value string) CredentialID {
	t.Helper()
	id, err := ParseCredentialID(value)
	if err != nil {
		t.Fatalf("parse credential id: %v", err)
	}
	return id
}
