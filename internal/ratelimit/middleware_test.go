package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestMiddlewareAllowsRequest(t *testing.T) {
	testutil.SetGinTestMode(t)
	checker := &fakeChecker{decision: Decision{Allowed: true, Limit: 10, Remaining: 9}}
	router := gin.New()
	router.GET("/auth/login", NewMiddleware(checker)(
		WithSubject(func(*gin.Context) Subject {
			return Subject{Username: "celeste"}
		}),
	), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	rec := testutil.Record(router, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if checker.request.Subject.Username != "celeste" {
		t.Fatalf("username = %q, want celeste", checker.request.Subject.Username)
	}
	if checker.request.Subject.Endpoint != "/auth/login" {
		t.Fatalf("endpoint = %q, want /auth/login", checker.request.Subject.Endpoint)
	}
	if got := rec.Header().Get("X-RateLimit-Remaining"); got != "9" {
		t.Fatalf("remaining header = %q, want 9", got)
	}
}

func TestMiddlewareRejectsLimitedRequest(t *testing.T) {
	testutil.SetGinTestMode(t)
	resetAt := time.Unix(1893456000, 0).UTC()
	checker := &fakeChecker{decision: Decision{
		Allowed:    false,
		Limit:      5,
		Remaining:  0,
		RetryAfter: 30 * time.Second,
		ResetAt:    resetAt,
	}}
	router := gin.New()
	router.POST("/password-reset", NewMiddleware(checker)(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	rec := testutil.Record(router, httptest.NewRequest(http.MethodPost, "/password-reset", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("retry-after = %q, want 30", got)
	}
	var body struct {
		Code string `json:"code"`
	}
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Code != "rate_limited" {
		t.Fatalf("code = %q, want rate_limited", body.Code)
	}
}

func TestMiddlewareFailsClosedWhenLimiterErrors(t *testing.T) {
	testutil.SetGinTestMode(t)
	checker := &fakeChecker{err: errors.New("redis down")}
	router := gin.New()
	router.GET("/auth/login", NewMiddleware(checker)(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	rec := testutil.Record(router, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

type fakeChecker struct {
	decision Decision
	err      error
	request  Request
}

func (c *fakeChecker) Check(_ context.Context, req Request) (Decision, error) {
	c.request = req
	return c.decision, c.err
}
