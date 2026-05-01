package account

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRegistrationServiceCreatesAccountWithNormalizedValues(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	accountID := mustRegistrationAccountID(t, "018f1f74-10a1-7000-9000-000000000201")
	emailID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000202")
	store := &fakeRegistrationStore{}
	audit := &fakeRegistrationAuditWriter{}
	service := NewRegistrationService(RegistrationDeps{
		Store: store,
		Audit: audit,
		IDs:   fakeRegistrationIDs{accountID: accountID, emailID: emailID},
		Clock: fakeRegistrationClock{now: now},
	})

	got, err := service.Register(ctx, RegistrationRequest{
		Username:      "  CELESTE_1  ",
		Email:         "  User@Example.COM  ",
		DisplayName:   " Celeste Love ",
		EmailVerified: true,
		RequestID:     "req_register",
		IP:            "2001:db8::1",
		UserAgent:     "registration-test",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if !got.Accepted || got.PublicMessage != RegistrationAcceptedMessage {
		t.Fatalf("result = %#v, want accepted generic message", got)
	}
	if !store.createCalled {
		t.Fatal("expected account creation")
	}
	if store.draft.AccountID != accountID || store.draft.EmailID != emailID {
		t.Fatalf("draft ids = %s/%s", store.draft.AccountID, store.draft.EmailID)
	}
	if store.draft.Username != "CELESTE_1" || store.draft.UsernameNormalized != "celeste_1" {
		t.Fatalf("username draft = %q/%q", store.draft.Username, store.draft.UsernameNormalized)
	}
	if store.draft.EmailAddress != "User@Example.COM" || store.draft.EmailNormalized != "user@example.com" {
		t.Fatalf("email draft = %q/%q", store.draft.EmailAddress, store.draft.EmailNormalized)
	}
	if store.draft.DisplayName != "Celeste Love" {
		t.Fatalf("display name = %q, want Celeste Love", store.draft.DisplayName)
	}
	if !store.draft.EmailVerified || !store.draft.EmailVerifiedAt.Equal(now) {
		t.Fatalf("email verification = %t/%v, want true/%v", store.draft.EmailVerified, store.draft.EmailVerifiedAt, now)
	}

	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	event := audit.events[0]
	if event.Type != AuditEventRegistrationAttempted || event.AccountID != accountID {
		t.Fatalf("audit event = %#v", event)
	}
	if event.Attributes["outcome"] != "created" || event.Attributes["reason"] != "created" || event.Attributes["email_verified"] != "true" {
		t.Fatalf("audit attributes = %#v", event.Attributes)
	}
	if event.Attributes["email"] != "" || event.Attributes["username"] != "" {
		t.Fatalf("audit attributes should not include raw username or email: %#v", event.Attributes)
	}
}

func TestRegistrationServiceAcceptsDuplicateIdentityWithoutCreating(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		usernameExists bool
		emailExists    bool
		wantReason     string
	}{
		{
			name:           "duplicate username",
			usernameExists: true,
			wantReason:     "duplicate_username",
		},
		{
			name:        "duplicate email",
			emailExists: true,
			wantReason:  "duplicate_email",
		},
		{
			name:           "duplicate username and email",
			usernameExists: true,
			emailExists:    true,
			wantReason:     "duplicate_username_email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeRegistrationStore{
				usernameExists: tt.usernameExists,
				emailExists:    tt.emailExists,
			}
			audit := &fakeRegistrationAuditWriter{}
			service := NewRegistrationService(RegistrationDeps{
				Store: store,
				Audit: audit,
				IDs:   fakeRegistrationIDs{},
				Clock: fakeRegistrationClock{now: now},
			})

			got, err := service.Register(ctx, RegistrationRequest{
				Username:  "celeste",
				Email:     "celeste@example.com",
				RequestID: "req_duplicate",
			})
			if err != nil {
				t.Fatalf("register duplicate: %v", err)
			}
			if !got.Accepted || got.PublicMessage != RegistrationAcceptedMessage {
				t.Fatalf("duplicate result = %#v, want accepted generic message", got)
			}
			if store.createCalled {
				t.Fatal("duplicate identity should not create an account")
			}
			if store.usernameChecked != "celeste" || store.emailChecked != "celeste@example.com" {
				t.Fatalf("availability checks = %q/%q", store.usernameChecked, store.emailChecked)
			}
			if len(audit.events) != 1 {
				t.Fatalf("audit events = %d, want 1", len(audit.events))
			}
			if audit.events[0].AccountID != (AccountID(uuid.Nil)) {
				t.Fatalf("duplicate audit account id = %s, want zero", audit.events[0].AccountID)
			}
			if audit.events[0].Attributes["outcome"] != "accepted_existing" || audit.events[0].Attributes["reason"] != tt.wantReason {
				t.Fatalf("audit attributes = %#v", audit.events[0].Attributes)
			}
		})
	}
}

func TestRegistrationServiceTreatsUniqueRaceAsAccepted(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	accountID := mustRegistrationAccountID(t, "018f1f74-10a1-7000-9000-000000000203")
	emailID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000204")
	store := &fakeRegistrationStore{createErr: ErrRegistrationIdentityTaken}
	audit := &fakeRegistrationAuditWriter{}
	service := NewRegistrationService(RegistrationDeps{
		Store: store,
		Audit: audit,
		IDs:   fakeRegistrationIDs{accountID: accountID, emailID: emailID},
		Clock: fakeRegistrationClock{now: now},
	})

	got, err := service.Register(ctx, RegistrationRequest{
		Username: "celeste",
		Email:    "celeste@example.com",
	})
	if err != nil {
		t.Fatalf("register unique race: %v", err)
	}
	if !got.Accepted || got.PublicMessage != RegistrationAcceptedMessage {
		t.Fatalf("race result = %#v, want accepted generic message", got)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	if audit.events[0].Attributes["outcome"] != "accepted_existing" || audit.events[0].Attributes["reason"] != "duplicate_identity" {
		t.Fatalf("audit attributes = %#v", audit.events[0].Attributes)
	}
}

func TestRegistrationServiceValidatesUsernameEmailAndDisplayName(t *testing.T) {
	service := NewRegistrationService(RegistrationDeps{
		Store: &fakeRegistrationStore{},
		Audit: &fakeRegistrationAuditWriter{},
		IDs:   fakeRegistrationIDs{},
		Clock: fakeRegistrationClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})

	tests := []struct {
		name      string
		req       RegistrationRequest
		wantField string
	}{
		{
			name:      "short username",
			req:       RegistrationRequest{Username: "ab", Email: "user@example.com"},
			wantField: "username",
		},
		{
			name:      "bad username characters",
			req:       RegistrationRequest{Username: "bad.name", Email: "user@example.com"},
			wantField: "username",
		},
		{
			name:      "bad email",
			req:       RegistrationRequest{Username: "celeste", Email: "not an email"},
			wantField: "email",
		},
		{
			name: "long display name",
			req: RegistrationRequest{
				Username:    "celeste",
				Email:       "user@example.com",
				DisplayName: stringsOfLength(displayNameMaxLen + 1),
			},
			wantField: "display_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Register(context.Background(), tt.req)
			if !errors.Is(err, ErrInvalidRegistration) {
				t.Fatalf("register error = %v, want invalid registration", err)
			}
			var validationErr *RegistrationValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error type = %T, want RegistrationValidationError", err)
			}
			if len(validationErr.Fields) == 0 || validationErr.Fields[0].Field != tt.wantField {
				t.Fatalf("validation fields = %#v, want first field %q", validationErr.Fields, tt.wantField)
			}
		})
	}
}

func TestNormalizeUsernameAndEmail(t *testing.T) {
	username, err := NormalizeUsername("  CELESTE-1  ")
	if err != nil {
		t.Fatalf("normalize username: %v", err)
	}
	if username != "celeste-1" {
		t.Fatalf("username = %q, want celeste-1", username)
	}

	email, err := NormalizeEmail("  User@Example.COM  ")
	if err != nil {
		t.Fatalf("normalize email: %v", err)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", email)
	}
}

type fakeRegistrationStore struct {
	usernameExists  bool
	emailExists     bool
	createErr       error
	createCalled    bool
	usernameChecked string
	emailChecked    string
	draft           AccountRegistrationDraft
}

func (s *fakeRegistrationStore) UsernameExists(_ context.Context, usernameNormalized string) (bool, error) {
	s.usernameChecked = usernameNormalized
	return s.usernameExists, nil
}

func (s *fakeRegistrationStore) EmailExists(_ context.Context, emailNormalized string) (bool, error) {
	s.emailChecked = emailNormalized
	return s.emailExists, nil
}

func (s *fakeRegistrationStore) CreateRegistration(_ context.Context, draft AccountRegistrationDraft) (RegisteredAccount, error) {
	s.createCalled = true
	s.draft = draft
	if s.createErr != nil {
		return RegisteredAccount{}, s.createErr
	}
	return RegisteredAccount{
		ID:              draft.AccountID,
		EmailID:         draft.EmailID,
		Username:        draft.Username,
		EmailAddress:    draft.EmailAddress,
		EmailVerified:   draft.EmailVerified,
		EmailVerifiedAt: draft.EmailVerifiedAt,
	}, nil
}

type fakeRegistrationAuditWriter struct {
	events []RegistrationAuditEvent
}

func (w *fakeRegistrationAuditWriter) WriteRegistrationAuditEvent(_ context.Context, event RegistrationAuditEvent) error {
	w.events = append(w.events, event)
	return nil
}

type fakeRegistrationIDs struct {
	accountID AccountID
	emailID   uuid.UUID
}

func (g fakeRegistrationIDs) NewAccountID() (AccountID, error) {
	if g.accountID.IsZero() {
		return mustParseRegistrationAccountID("018f1f74-10a1-7000-9000-000000000299"), nil
	}
	return g.accountID, nil
}

func (g fakeRegistrationIDs) NewEmailID() (uuid.UUID, error) {
	if g.emailID == uuid.Nil {
		return uuid.MustParse("018f1f74-10a1-7000-9000-000000000298"), nil
	}
	return g.emailID, nil
}

type fakeRegistrationClock struct {
	now time.Time
}

func (c fakeRegistrationClock) Now() time.Time {
	return c.now
}

func mustRegistrationAccountID(t testing.TB, value string) AccountID {
	t.Helper()
	return mustParseRegistrationAccountID(value)
}

func mustParseRegistrationAccountID(value string) AccountID {
	id, err := ParseAccountID(value)
	if err != nil {
		panic(err)
	}
	return id
}

func stringsOfLength(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte('x')
	}
	return b.String()
}
