package account

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/authctx"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestAccountModuleProfileRoutes(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000501")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	profiles := &fakeProfileManager{
		profile: AccountProfile{
			ID:          accountID,
			Username:    "celeste",
			DisplayName: "Celeste",
			Metadata:    json.RawMessage(`{"timezone":"America/Bogota"}`),
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	router := accountTestRouter(t, New(Deps{Profiles: profiles}), authenticatedAs(accountID, time.Time{}))

	getRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/profile", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", getRec.Code, http.StatusOK)
	}
	var getBody map[string]any
	testutil.DecodeJSON(t, getRec.Body, &getBody)
	if getBody["id"] != accountID.String() || getBody["display_name"] != "Celeste" {
		t.Fatalf("profile body = %#v", getBody)
	}

	patchRec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPatch, "/account/profile", map[string]any{
		"display_name": " Celeste Love ",
		"metadata": map[string]any{
			"locale": "en-US",
		},
	}))
	if patchRec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want %d", patchRec.Code, http.StatusOK)
	}
	if !profiles.update.DisplayNameSet || profiles.update.DisplayName != " Celeste Love " || !profiles.update.MetadataSet {
		t.Fatalf("profile update request = %#v", profiles.update)
	}
}

func TestAccountModuleListsCredentialsWithoutSecrets(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000502")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000503")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	credentials := &fakeCredentialManager{
		credentials: []Credential{
			{
				ID:              credentialID,
				AccountID:       accountID,
				Kind:            CredentialKindOIDC,
				Provider:        "github",
				ExternalSubject: "sub-123",
				DisplayName:     "GitHub",
				Verified:        true,
				CreatedAt:       now,
				UpdatedAt:       now,
				LastUsedAt:      now,
				Payload: CredentialPayload{
					Ciphertext: []byte("secret-ciphertext"),
				},
			},
		},
	}
	router := accountTestRouter(t, New(Deps{Credentials: credentials}), authenticatedAs(accountID, time.Time{}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/credentials", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret-ciphertext", "external_subject", "sub-123", "payload"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("credential response leaked %q: %s", forbidden, body)
		}
	}
	var decoded credentialsResponse
	testutil.DecodeJSON(t, strings.NewReader(body), &decoded)
	if len(decoded.Credentials) != 1 || decoded.Credentials[0].Provider != "github" {
		t.Fatalf("credentials response = %#v", decoded)
	}
}

func TestAccountModuleRemoveCredentialUsesReauthenticationContext(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000504")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000505")
	reauthenticatedAt := time.Date(2026, 5, 1, 11, 59, 0, 0, time.UTC)
	credentials := &fakeCredentialManager{}
	router := accountTestRouter(t, New(Deps{Credentials: credentials}), authenticatedAs(accountID, reauthenticatedAt))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/credentials/"+credentialID.String(), nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if credentials.remove.AccountID != accountID || credentials.remove.CredentialID != credentialID || !credentials.remove.ReauthenticatedAt.Equal(reauthenticatedAt) {
		t.Fatalf("remove request = %#v", credentials.remove)
	}
}

func TestAccountModuleRemoveCredentialProtectsLastCredential(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000506")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000507")
	credentials := &fakeCredentialManager{removeErr: ErrLastCredential}
	router := accountTestRouter(t, New(Deps{Credentials: credentials}), authenticatedAs(accountID, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodDelete, "/account/credentials/"+credentialID.String(), nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["code"] != "last_credential" {
		t.Fatalf("problem body = %#v", body)
	}
}

func TestAccountModuleRequiresAuthentication(t *testing.T) {
	router := accountTestRouter(t, New(Deps{Profiles: &fakeProfileManager{}}), func(c *gin.Context) {
		c.Next()
	})

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/account/profile", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func accountTestRouter(t testing.TB, module *Module, auth gin.HandlerFunc) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	module.RegisterRoutes(router.Group("/account"), httpapi.Middlewares{Authenticate: auth})
	return router
}

func authenticatedAs(accountID AccountID, reauthenticatedAt time.Time) gin.HandlerFunc {
	return func(c *gin.Context) {
		authctx.SetAccountID(c, accountID.String())
		if !reauthenticatedAt.IsZero() {
			authctx.SetReauthenticatedAt(c, reauthenticatedAt)
		}
		c.Next()
	}
}

type fakeProfileManager struct {
	profile AccountProfile
	update  UpdateProfileRequest
	err     error
}

func (m *fakeProfileManager) GetProfile(context.Context, AccountID) (AccountProfile, error) {
	if m.err != nil {
		return AccountProfile{}, m.err
	}
	return m.profile, nil
}

func (m *fakeProfileManager) UpdateProfile(_ context.Context, req UpdateProfileRequest) (AccountProfile, error) {
	m.update = req
	if m.err != nil {
		return AccountProfile{}, m.err
	}
	profile := m.profile
	profile.DisplayName = req.DisplayName
	profile.Metadata = req.Metadata
	return profile, nil
}

type fakeCredentialManager struct {
	credentials []Credential
	remove      RemoveCredentialRequest
	listErr     error
	removeErr   error
}

func (m *fakeCredentialManager) ListCredentials(context.Context, AccountID) ([]Credential, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.credentials, nil
}

func (m *fakeCredentialManager) RemoveCredential(_ context.Context, req RemoveCredentialRequest) (Credential, error) {
	m.remove = req
	if m.removeErr != nil {
		return Credential{}, m.removeErr
	}
	return Credential{ID: req.CredentialID, AccountID: req.AccountID}, nil
}
