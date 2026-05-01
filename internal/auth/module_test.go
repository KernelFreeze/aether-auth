package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestAuthModuleRegisterReturnsAcceptedPublicResponse(t *testing.T) {
	store := &registrationStore{}
	registration := account.NewRegistrationService(account.RegistrationDeps{
		Store: store,
		Audit: &registrationAuditWriter{},
		IDs: registrationIDs{
			accountID: mustAccountID(t, "018f1f74-10a1-7000-9000-000000000601"),
			emailID:   uuid.MustParse("018f1f74-10a1-7000-9000-000000000602"),
		},
		Clock: registrationClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})
	router := authTestRouter(t, New(Deps{Registration: registration}))

	req := testutil.NewJSONRequest(t, http.MethodPost, "/auth/register", map[string]any{
		"username":     " Celeste_1 ",
		"email":        " User@Example.COM ",
		"display_name": " Celeste Love ",
	})
	req.Header.Set("X-Request-Id", "req-register")
	req.Header.Set("User-Agent", "registration-test")
	rec := testutil.Record(router, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	var body registrationResponse
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Message != account.RegistrationAcceptedMessage {
		t.Fatalf("message = %q, want %q", body.Message, account.RegistrationAcceptedMessage)
	}
	if store.draft.UsernameNormalized != "celeste_1" || store.draft.EmailNormalized != "user@example.com" {
		t.Fatalf("draft = %#v", store.draft)
	}
}

func TestAuthModuleRegisterDoesNotRevealDuplicateIdentity(t *testing.T) {
	tests := []struct {
		name           string
		usernameExists bool
		emailExists    bool
	}{
		{name: "new account"},
		{name: "duplicate username", usernameExists: true},
		{name: "duplicate email", emailExists: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registration := account.NewRegistrationService(account.RegistrationDeps{
				Store: &registrationStore{
					usernameExists: tt.usernameExists,
					emailExists:    tt.emailExists,
				},
				Audit: &registrationAuditWriter{},
				IDs: registrationIDs{
					accountID: mustAccountID(t, "018f1f74-10a1-7000-9000-000000000603"),
					emailID:   uuid.MustParse("018f1f74-10a1-7000-9000-000000000604"),
				},
				Clock: registrationClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
			})
			router := authTestRouter(t, New(Deps{Registration: registration}))

			rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/register", map[string]any{
				"username": "celeste",
				"email":    "celeste@example.com",
			}))

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
			}
			got := canonicalRegistrationJSON(t, rec.Body.Bytes())
			want := canonicalRegistrationJSON(t, []byte(`{"message":"If the account can be created, check your email."}`))
			if got != want {
				t.Fatalf("body = %s, want %s", got, want)
			}
			for _, forbidden := range []string{"duplicate", "taken", "exists", "account_id", "email_normalized"} {
				if strings.Contains(got, forbidden) {
					t.Fatalf("registration response leaked %q: %s", forbidden, got)
				}
			}
		})
	}
}

func TestAuthModuleRegisterValidatesRequest(t *testing.T) {
	router := authTestRouter(t, New(Deps{Registration: account.NewRegistrationService(account.RegistrationDeps{
		Store: &registrationStore{},
		Audit: &registrationAuditWriter{},
		IDs:   registrationIDs{},
		Clock: registrationClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
	})}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/register", map[string]any{
		"username": "ab",
		"email":    "not an email",
	}))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body httpxProblem
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Code != "invalid_registration" || len(body.Fields) == 0 {
		t.Fatalf("problem = %#v", body)
	}
}

func authTestRouter(t testing.TB, module *Module) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	router.Use(middleware.RequestIDMiddleware())
	module.RegisterRoutes(router.Group("/auth"), httpapi.Middlewares{})
	return router
}

func canonicalRegistrationJSON(t testing.TB, data []byte) string {
	t.Helper()

	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	canonical, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return string(canonical)
}

type httpxProblem struct {
	Code   string `json:"code"`
	Fields []struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"fields"`
}

type registrationStore struct {
	usernameExists bool
	emailExists    bool
	draft          account.AccountRegistrationDraft
}

func (s *registrationStore) UsernameExists(_ context.Context, usernameNormalized string) (bool, error) {
	return s.usernameExists, nil
}

func (s *registrationStore) EmailExists(_ context.Context, emailNormalized string) (bool, error) {
	return s.emailExists, nil
}

func (s *registrationStore) CreateRegistration(_ context.Context, draft account.AccountRegistrationDraft) (account.RegisteredAccount, error) {
	s.draft = draft
	return account.RegisteredAccount{
		ID:              draft.AccountID,
		EmailID:         draft.EmailID,
		Username:        draft.Username,
		EmailAddress:    draft.EmailAddress,
		EmailVerified:   draft.EmailVerified,
		EmailVerifiedAt: draft.EmailVerifiedAt,
	}, nil
}

type registrationAuditWriter struct{}

func (w *registrationAuditWriter) WriteRegistrationAuditEvent(context.Context, account.RegistrationAuditEvent) error {
	return nil
}

type registrationIDs struct {
	accountID account.AccountID
	emailID   uuid.UUID
}

func (g registrationIDs) NewAccountID() (account.AccountID, error) {
	if g.accountID.IsZero() {
		return account.ParseAccountID("018f1f74-10a1-7000-9000-000000000699")
	}
	return g.accountID, nil
}

func (g registrationIDs) NewEmailID() (uuid.UUID, error) {
	if g.emailID == uuid.Nil {
		return uuid.MustParse("018f1f74-10a1-7000-9000-000000000698"), nil
	}
	return g.emailID, nil
}

type registrationClock struct {
	now time.Time
}

func (c registrationClock) Now() time.Time {
	return c.now
}
