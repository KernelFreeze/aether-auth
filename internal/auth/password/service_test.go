package password

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

func TestSetPasswordChecksPolicyBreachAndStoresEncryptedHash(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000001001")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000001002")
	repo := &fakeCredentialRepository{createdID: credentialID}
	hasher := &fakePasswordHasher{hash: auth.PasswordHash{PHCString: "phc-new", ParamsID: "params"}}
	breaches := &fakeBreachChecker{}
	service := New(Deps{
		Credentials: repo,
		Hasher:      hasher,
		Policy:      NISTPolicy{},
		Breaches:    breaches,
		Box:         fakeSecretBox{},
	})

	created, err := service.SetPassword(context.Background(), SetPasswordRequest{
		AccountID: accountID,
		Password:  "correct horse battery staple",
		Username:  "celeste",
		Email:     "celeste@example.com",
	})
	if err != nil {
		t.Fatalf("set password: %v", err)
	}

	if created.ID != credentialID || repo.create.Kind != account.CredentialKindPassword || !repo.create.Verified {
		t.Fatalf("created credential = %#v / draft %#v", created, repo.create)
	}
	if bytes.Contains(repo.create.EncryptedPayload, []byte("correct horse")) {
		t.Fatalf("encrypted payload contains raw password: %s", repo.create.EncryptedPayload)
	}
	if hasher.hashReq.Password != "correct horse battery staple" || breaches.req.Password == "" {
		t.Fatalf("password checks did not receive password input")
	}
}

func TestSetPasswordRejectsShortAndBreachedPasswords(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000001003")

	tests := []struct {
		name     string
		password string
		breached bool
	}{
		{name: "short", password: "short"},
		{name: "breached", password: "long enough", breached: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(Deps{
				Credentials: &fakeCredentialRepository{},
				Hasher:      &fakePasswordHasher{hash: auth.PasswordHash{PHCString: "phc"}},
				Policy:      NISTPolicy{},
				Breaches:    &fakeBreachChecker{result: auth.PasswordBreachResult{Breached: tt.breached}},
				Box:         fakeSecretBox{},
			})

			_, err := service.SetPassword(context.Background(), SetPasswordRequest{
				AccountID: accountID,
				Password:  tt.password,
			})
			if !errors.Is(err, auth.ErrPolicyDenied) {
				t.Fatalf("set password error = %v, want policy denied", err)
			}
		})
	}
}

func TestVerifyPasswordUpdatesLastUsedAndRehashes(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000001004")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000001005")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	repo := &fakeCredentialRepository{}
	hasher := &fakePasswordHasher{
		verify: auth.PasswordVerifyResult{Matched: true, NeedsRehash: true},
		hash:   auth.PasswordHash{PHCString: "phc-new", ParamsID: "new"},
	}
	service := New(Deps{
		Credentials: repo,
		Hasher:      hasher,
		Policy:      NISTPolicy{},
		Box:         fakeSecretBox{},
		Attempts:    &fakeAttemptStore{},
		Clock:       fakeClock{now: now},
	})
	payload, err := service.sealHash(context.Background(), accountID, auth.PasswordHash{PHCString: "phc-old", ParamsID: "old"})
	if err != nil {
		t.Fatalf("seal hash: %v", err)
	}
	repo.lookup = auth.CredentialSnapshot{
		ID:               credentialID,
		AccountID:        accountID,
		Kind:             account.CredentialKindPassword,
		EncryptedPayload: payload,
		Verified:         true,
	}

	result, err := service.Verify(context.Background(), auth.VerifyRequest{
		AccountHint:     accountID,
		Username:        "celeste",
		CredentialInput: "correct horse battery staple",
		MFARequired:     true,
		IP:              netip.MustParseAddr("203.0.113.20"),
	})
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if result.AccountID != accountID || result.CredentialID != credentialID || result.MFAStatus != auth.MFAStatusRequired || !result.Session.Partial {
		t.Fatalf("auth result = %#v", result)
	}
	if repo.update.CredentialID != credentialID || repo.update.LastUsedAt != now || len(repo.update.EncryptedPayload) == 0 {
		t.Fatalf("credential update = %#v", repo.update)
	}
	if hasher.verifyReq.Hash.PHCString != "phc-old" || hasher.hashReq.Password != "correct horse battery staple" {
		t.Fatalf("hasher calls = %#v / %#v", hasher.verifyReq, hasher.hashReq)
	}
}

func TestVerifyPasswordFailureRecordsLockout(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000001006")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000001007")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	attempts := &fakeAttemptStore{failure: AttemptResult{FailedCount: 5, LockedUntil: now.Add(time.Minute)}}
	repo := &fakeCredentialRepository{}
	service := New(Deps{
		Credentials: repo,
		Hasher:      &fakePasswordHasher{verify: auth.PasswordVerifyResult{Matched: false}},
		Policy:      NISTPolicy{},
		Box:         fakeSecretBox{},
		Attempts:    attempts,
		Clock:       fakeClock{now: now},
	})
	payload, err := service.sealHash(context.Background(), accountID, auth.PasswordHash{PHCString: "phc-old"})
	if err != nil {
		t.Fatalf("seal hash: %v", err)
	}
	repo.lookup = auth.CredentialSnapshot{
		ID:               credentialID,
		AccountID:        accountID,
		Kind:             account.CredentialKindPassword,
		EncryptedPayload: payload,
	}

	_, err = service.Verify(context.Background(), auth.VerifyRequest{
		AccountHint:     accountID,
		Username:        "celeste",
		CredentialInput: "wrong password",
		IP:              netip.MustParseAddr("203.0.113.21"),
	})
	if !errors.Is(err, auth.ErrLockedAccount) {
		t.Fatalf("verify error = %v, want locked account", err)
	}
	if attempts.fail.AccountID != accountID || attempts.fail.Username != "celeste" {
		t.Fatalf("recorded failure = %#v", attempts.fail)
	}
	if repo.update.CredentialID != (account.CredentialID{}) {
		t.Fatalf("credential should not be updated on failure: %#v", repo.update)
	}
}

func TestRunDummyPasswordWorkUsesDummyHash(t *testing.T) {
	hasher := &fakePasswordHasher{verify: auth.PasswordVerifyResult{Matched: false}}
	service := New(Deps{
		Hasher:    hasher,
		DummyHash: auth.PasswordHash{PHCString: "dummy-phc"},
	})

	if err := service.RunDummyPasswordWork(context.Background(), auth.DummyPasswordWorkRequest{CredentialInput: "wrong password"}); err != nil {
		t.Fatalf("dummy work: %v", err)
	}
	if hasher.verifyReq.Hash.PHCString != "dummy-phc" {
		t.Fatalf("dummy verify request = %#v", hasher.verifyReq)
	}
}

type fakeCredentialRepository struct {
	createdID account.CredentialID
	lookup    auth.CredentialSnapshot
	create    auth.CredentialDraft
	update    auth.CredentialUpdate
}

func (r *fakeCredentialRepository) LookupCredential(context.Context, auth.CredentialLookup) (auth.CredentialSnapshot, error) {
	if r.lookup.ID.IsZero() {
		return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
	}
	return r.lookup, nil
}

func (r *fakeCredentialRepository) CreateCredential(_ context.Context, draft auth.CredentialDraft) (auth.CredentialSnapshot, error) {
	r.create = draft
	id := r.createdID
	if id.IsZero() {
		id = mustCredentialIDNoT("018f1f74-10a1-7000-9000-000000001099")
	}
	return auth.CredentialSnapshot{
		ID:               id,
		AccountID:        draft.AccountID,
		Kind:             draft.Kind,
		EncryptedPayload: append([]byte(nil), draft.EncryptedPayload...),
		Verified:         draft.Verified,
	}, nil
}

func (r *fakeCredentialRepository) UpdateCredential(_ context.Context, update auth.CredentialUpdate) (auth.CredentialSnapshot, error) {
	r.update = update
	if r.lookup.ID.IsZero() {
		r.lookup.ID = update.CredentialID
	}
	if len(update.EncryptedPayload) > 0 {
		r.lookup.EncryptedPayload = append([]byte(nil), update.EncryptedPayload...)
	}
	r.lookup.LastUsedAt = update.LastUsedAt
	return r.lookup, nil
}

func (r *fakeCredentialRepository) CanRemoveCredential(context.Context, account.AccountID, account.CredentialID) (bool, error) {
	return true, nil
}

type fakePasswordHasher struct {
	hash      auth.PasswordHash
	verify    auth.PasswordVerifyResult
	hashReq   auth.PasswordHashRequest
	verifyReq auth.PasswordVerifyRequest
}

func (h *fakePasswordHasher) HashPassword(_ context.Context, req auth.PasswordHashRequest) (auth.PasswordHash, error) {
	h.hashReq = req
	return h.hash, nil
}

func (h *fakePasswordHasher) VerifyPassword(_ context.Context, req auth.PasswordVerifyRequest) (auth.PasswordVerifyResult, error) {
	h.verifyReq = req
	return h.verify, nil
}

type fakeBreachChecker struct {
	req    auth.PasswordBreachRequest
	result auth.PasswordBreachResult
}

func (c *fakeBreachChecker) CheckPasswordBreach(_ context.Context, req auth.PasswordBreachRequest) (auth.PasswordBreachResult, error) {
	c.req = req
	return c.result, nil
}

type fakeSecretBox struct{}

func (fakeSecretBox) Seal(_ context.Context, req auth.SecretBoxSealRequest) (auth.SecretBoxPayload, error) {
	return auth.SecretBoxPayload{KeyID: "test", Ciphertext: append([]byte("sealed:"), req.Plaintext...)}, nil
}

func (fakeSecretBox) Open(_ context.Context, req auth.SecretBoxOpenRequest) ([]byte, error) {
	return bytes.TrimPrefix(req.Payload.Ciphertext, []byte("sealed:")), nil
}

type fakeAttemptStore struct {
	failure AttemptResult
	fail    AttemptFailure
	success AttemptSuccess
}

func (s *fakeAttemptStore) RecordFailure(_ context.Context, failure AttemptFailure) (AttemptResult, error) {
	s.fail = failure
	return s.failure, nil
}

func (s *fakeAttemptStore) RecordSuccess(_ context.Context, success AttemptSuccess) error {
	s.success = success
	return nil
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}

func mustAccountID(t testing.TB, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func mustCredentialID(t testing.TB, value string) account.CredentialID {
	t.Helper()
	id, err := account.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("parse credential id: %v", err)
	}
	return id
}

func mustCredentialIDNoT(value string) account.CredentialID {
	id, err := account.ParseCredentialID(value)
	if err != nil {
		panic(err)
	}
	return id
}
