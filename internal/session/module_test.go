package session

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestSessionModuleRefreshReturnsReplacementTokens(t *testing.T) {
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000861")
	expiresAt := time.Date(2026, 5, 2, 17, 15, 0, 0, time.UTC)
	refresher := &refreshManager{
		result: RefreshSessionResult{
			SessionID:    sessionID,
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresAt:    expiresAt,
		},
	}
	router := sessionTestRouter(t, New(Deps{Refresher: refresher}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/session/refresh", map[string]any{
		"refresh_token": "old-refresh-token",
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body refreshResponse
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Status != "refreshed" || body.Session.ID != sessionID.String() || body.Session.AccessToken != "new-access-token" || body.Session.RefreshToken != "new-refresh-token" {
		t.Fatalf("refresh response = %#v", body)
	}
	if refresher.req.RefreshToken != "old-refresh-token" {
		t.Fatalf("refresh request = %#v", refresher.req)
	}
}

func TestSessionModuleRefreshUsesGenericReuseError(t *testing.T) {
	router := sessionTestRouter(t, New(Deps{Refresher: &refreshManager{
		err: auth.NewServiceError(auth.ErrorKindInvalidCredentials, "refresh token has already been used", nil),
	}}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/session/refresh", map[string]any{
		"refresh_token": "old-refresh-token",
	}))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Code != "invalid_refresh_token" {
		t.Fatalf("problem = %#v", body)
	}
	for _, forbidden := range []string{"used", "reuse", "revoke", "chain"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("refresh error leaked %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestSessionModuleRefreshValidatesBody(t *testing.T) {
	router := sessionTestRouter(t, New(Deps{Refresher: &refreshManager{}}))

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/session/refresh", map[string]any{
		"refresh_token": "",
	}))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func sessionTestRouter(t testing.TB, module *Module) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	module.RegisterRoutes(router.Group("/session"), httpapi.Middlewares{})
	return router
}

type refreshManager struct {
	req    RefreshSessionRequest
	result RefreshSessionResult
	err    error
}

func (m *refreshManager) RefreshSession(_ context.Context, req RefreshSessionRequest) (RefreshSessionResult, error) {
	m.req = req
	if m.err != nil {
		return RefreshSessionResult{}, m.err
	}
	return m.result, nil
}
