package session

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/authctx"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestAuthenticationMiddlewareSetsVerifiedSessionContext(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000911")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000912")
	issuedAt := time.Now().Add(-time.Minute).UTC()
	raw := issueAccessToken(t, accountID, sessionID, account.ClientID{}, "access-jti", issuedAt, issuedAt.Add(time.Hour), []string{"profile:read", "email:read"})
	store := &fakeStore{
		revoked: SessionRecord{
			ID:        sessionID,
			AccountID: accountID,
			Kind:      sessionKindFull,
			Status:    sessionStatusActive,
			TokenID:   "access-jti",
			ExpiresAt: issuedAt.Add(90 * 24 * time.Hour),
		},
	}
	router := authRouter(t, AuthenticationDeps{
		Tokens:      newTestKeystore(t),
		Sessions:    store,
		Revocations: &fakeRevocationCache{},
		Issuer:      "https://auth.example.test",
	})

	req := testutil.NewJSONRequest(t, http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := testutil.Record(router, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["account_id"] != accountID.String() || body["session_id"] != sessionID.String() || body["token_id"] != "access-jti" {
		t.Fatalf("auth context = %#v", body)
	}
}

func TestAuthenticationMiddlewareRejectsRevokedAccessTokenID(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000921")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000922")
	issuedAt := time.Now().Add(-time.Minute).UTC()
	raw := issueAccessToken(t, accountID, sessionID, account.ClientID{}, "revoked-jti", issuedAt, issuedAt.Add(time.Hour), nil)
	router := authRouter(t, AuthenticationDeps{
		Tokens: newTestKeystore(t),
		Sessions: &fakeStore{revoked: SessionRecord{
			ID:        sessionID,
			AccountID: accountID,
			Kind:      sessionKindFull,
			Status:    sessionStatusActive,
			TokenID:   "revoked-jti",
			ExpiresAt: issuedAt.Add(90 * 24 * time.Hour),
		}},
		Revocations: &fakeRevocationCache{revoked: true},
		Issuer:      "https://auth.example.test",
	})

	req := testutil.NewJSONRequest(t, http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := testutil.Record(router, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAuthenticationMiddlewareRejectsRevokedSession(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000931")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000932")
	issuedAt := time.Now().Add(-time.Minute).UTC()
	raw := issueAccessToken(t, accountID, sessionID, account.ClientID{}, "access-jti", issuedAt, issuedAt.Add(time.Hour), nil)
	router := authRouter(t, AuthenticationDeps{
		Tokens: newTestKeystore(t),
		Sessions: &fakeStore{revoked: SessionRecord{
			ID:        sessionID,
			AccountID: accountID,
			Kind:      sessionKindFull,
			Status:    sessionStatusRevoked,
			TokenID:   "access-jti",
		}},
		Revocations: &fakeRevocationCache{},
		Issuer:      "https://auth.example.test",
	})

	req := testutil.NewJSONRequest(t, http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := testutil.Record(router, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAuthenticationMiddlewareRejectsPartialSessionToken(t *testing.T) {
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000941")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000942")
	issuedAt := time.Now().Add(-time.Minute).UTC()
	ks := newTestKeystore(t)
	partial, err := ks.IssuePartialSessionToken(context.Background(), paseto.IssueRequest{
		Claims: partialClaims(partialClaimInput{
			Issuer:    "https://auth.example.test",
			AccountID: accountID,
			SessionID: sessionID,
			TokenID:   "partial-jti",
			Factors:   []account.FactorKind{account.FactorKindUser},
			IssuedAt:  issuedAt,
			ExpiresAt: issuedAt.Add(time.Minute),
		}),
		Implicit: implicitAssertion("partial", accountID, sessionID, account.ClientID{}),
	})
	if err != nil {
		t.Fatalf("issue partial token: %v", err)
	}
	router := authRouter(t, AuthenticationDeps{
		Tokens:      ks,
		Sessions:    &fakeStore{},
		Revocations: &fakeRevocationCache{},
		Issuer:      "https://auth.example.test",
	})

	req := testutil.NewJSONRequest(t, http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+partial)
	rec := testutil.Record(router, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func authRouter(t testing.TB, deps AuthenticationDeps) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	router.GET("/protected", NewAuthenticationMiddleware(deps), func(c *gin.Context) {
		accountID, _ := authctx.AccountID(c)
		sessionID, _ := authctx.SessionID(c)
		tokenID, _ := authctx.AccessTokenID(c)
		scopes, _ := authctx.Scopes(c)
		c.JSON(http.StatusOK, gin.H{
			"account_id": accountID,
			"session_id": sessionID,
			"token_id":   tokenID,
			"scopes":     scopes,
		})
	})
	return router
}

func issueAccessToken(t testing.TB, accountID account.AccountID, sessionID account.SessionID, clientID account.ClientID, tokenID string, issuedAt, expiresAt time.Time, scopes []string) string {
	t.Helper()
	ks := newTestKeystore(t)
	raw, err := ks.IssueAccessToken(context.Background(), paseto.IssueRequest{
		Claims: accessClaims(accessClaimInput{
			Issuer:    "https://auth.example.test",
			AccountID: accountID,
			SessionID: sessionID,
			ClientID:  clientID,
			TokenID:   tokenID,
			Scopes:    scopes,
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
		}),
		Implicit: implicitAssertion("access", accountID, sessionID, clientID),
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	return raw
}
