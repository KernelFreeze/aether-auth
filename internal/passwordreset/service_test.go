package passwordreset

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestServiceRequestResetCreatesTokenAndQueuesEmail(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000801")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	store := &resetStore{
		target: ResetTarget{
			AccountID: accountID,
			Username:  "celeste",
			Email:     "celeste@example.test",
		},
	}
	email := &emailQueue{}
	service := NewService(ServiceDeps{
		Store:         store,
		EmailQueue:    email,
		IDs:           resetIDs{id: uuid.MustParse("018f1f74-10a1-7000-9000-000000000802")},
		Random:        testutil.NewDeterministicReader([]byte{0x42}),
		Clock:         testutil.NewFakeClock(now),
		TokenTTL:      30 * time.Minute,
		PublicBaseURL: "https://auth.example.test/base",
	})

	_, err := service.RequestReset(context.Background(), RequestResetRequest{
		Username:  " Celeste ",
		IP:        "203.0.113.4",
		UserAgent: "reset-test",
		RequestID: "req-reset",
	})
	if err != nil {
		t.Fatalf("request reset: %v", err)
	}

	if store.lookup.Username != "celeste" {
		t.Fatalf("lookup = %#v", store.lookup)
	}
	if store.draft.AccountID != accountID || store.draft.RequestedByIP != "203.0.113.4" || store.draft.UserAgent != "reset-test" {
		t.Fatalf("draft = %#v", store.draft)
	}
	if !store.draft.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("expires = %v, want %v", store.draft.ExpiresAt, now.Add(30*time.Minute))
	}
	if email.email.To != "celeste@example.test" || email.email.RequestID != "req-reset" {
		t.Fatalf("email = %#v", email.email)
	}

	resetURL, err := url.Parse(email.email.ResetURL)
	if err != nil {
		t.Fatalf("parse reset url: %v", err)
	}
	if resetURL.Scheme != "https" || resetURL.Host != "auth.example.test" || resetURL.Path != "/base/reset-password" {
		t.Fatalf("reset url = %s", resetURL.String())
	}
	token := resetURL.Query().Get("token")
	if token == "" {
		t.Fatalf("reset url has no token: %s", resetURL.String())
	}
	wantToken := base64.RawURLEncoding.EncodeToString(bytesOf(0x42, resetTokenBytes))
	if token != wantToken {
		t.Fatalf("token = %q, want deterministic token", token)
	}
	wantHash := sha256.Sum256([]byte(token))
	if string(store.draft.TokenHash) != string(wantHash[:]) {
		t.Fatalf("token hash = %x, want %x", store.draft.TokenHash, wantHash)
	}
}

func TestServiceRequestResetUnknownAccountIsAcceptedWithoutEmail(t *testing.T) {
	store := &resetStore{err: auth.ErrInvalidCredentials}
	email := &emailQueue{}
	service := NewService(ServiceDeps{
		Store:         store,
		EmailQueue:    email,
		Random:        testutil.NewDeterministicReader([]byte{0x42}),
		PublicBaseURL: "https://auth.example.test",
	})

	if _, err := service.RequestReset(context.Background(), RequestResetRequest{Email: "missing@example.test"}); err != nil {
		t.Fatalf("request reset: %v", err)
	}
	if store.created {
		t.Fatal("created reset token for unknown account")
	}
	if email.called {
		t.Fatal("queued reset email for unknown account")
	}
}

func TestServiceRequestResetLockedLookupIsAccepted(t *testing.T) {
	service := NewService(ServiceDeps{
		Store:         &resetStore{err: auth.ErrLockedAccount},
		EmailQueue:    &emailQueue{},
		Random:        testutil.NewDeterministicReader([]byte{0x42}),
		PublicBaseURL: "https://auth.example.test",
	})

	if _, err := service.RequestReset(context.Background(), RequestResetRequest{Username: "locked"}); err != nil {
		t.Fatalf("request reset for locked account: %v", err)
	}
}

func TestServiceRequestResetRejectsAmbiguousIdentifier(t *testing.T) {
	service := NewService(ServiceDeps{
		Store:         &resetStore{},
		EmailQueue:    &emailQueue{},
		Random:        testutil.NewDeterministicReader([]byte{0x42}),
		PublicBaseURL: "https://auth.example.test",
	})

	_, err := service.RequestReset(context.Background(), RequestResetRequest{
		Username: "celeste",
		Email:    "celeste@example.test",
	})
	if !errors.Is(err, auth.ErrMalformedInput) {
		t.Fatalf("error = %v, want malformed input", err)
	}
}

func mustAccountID(t testing.TB, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func bytesOf(value byte, count int) []byte {
	b := make([]byte, count)
	for i := range b {
		b[i] = value
	}
	return b
}

type resetStore struct {
	lookup  ResetLookup
	target  ResetTarget
	draft   ResetTokenDraft
	err     error
	created bool
}

func (s *resetStore) LookupResetTarget(_ context.Context, lookup ResetLookup) (ResetTarget, error) {
	s.lookup = lookup
	if s.err != nil {
		return ResetTarget{}, s.err
	}
	return s.target, nil
}

func (s *resetStore) CreateResetToken(_ context.Context, draft ResetTokenDraft) error {
	s.created = true
	s.draft = draft
	return nil
}

type emailQueue struct {
	email  ResetEmail
	called bool
}

func (q *emailQueue) EnqueuePasswordResetEmail(_ context.Context, email ResetEmail) error {
	q.called = true
	q.email = email
	return nil
}

type resetIDs struct {
	id uuid.UUID
}

func (g resetIDs) NewResetTokenID() (uuid.UUID, error) {
	return g.id, nil
}
