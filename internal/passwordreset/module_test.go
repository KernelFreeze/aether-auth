package passwordreset

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
	"github.com/KernelFreeze/aether-auth/internal/ratelimit"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestModuleRequestResetReturnsGenericAcceptedResponse(t *testing.T) {
	for _, err := range []error{
		nil,
		auth.ErrInvalidCredentials,
		auth.ErrLockedAccount,
		auth.ErrMalformedInput,
	} {
		t.Run(errorName(err), func(t *testing.T) {
			requester := &requester{err: err}
			router := resetTestRouter(t, New(Deps{Requester: requester}), httpapi.Middlewares{})

			req := testutil.NewJSONRequest(t, http.MethodPost, "/auth/reset-password/request", map[string]any{
				"username": " Celeste ",
			})
			req.Header.Set("X-Request-Id", "req-reset")
			req.Header.Set("User-Agent", "reset-test")
			rec := testutil.Record(router, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusAccepted, rec.Body.String())
			}
			var body httpx.Problem
			testutil.DecodeJSON(t, rec.Body, &body)
			if body.Code != "reset_request_accepted" {
				t.Fatalf("problem = %#v", body)
			}
			if requester.req.Username != " Celeste " || requester.req.RequestID != "req-reset" || requester.req.UserAgent != "reset-test" {
				t.Fatalf("request = %#v", requester.req)
			}
		})
	}
}

func TestModuleRequestResetRejectsUnexpectedErrors(t *testing.T) {
	router := resetTestRouter(t, New(Deps{Requester: &requester{err: errors.New("database down")}}), httpapi.Middlewares{})

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/reset-password/request", map[string]any{
		"email": "celeste@example.test",
	}))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var body httpx.Problem
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Code != "internal_error" {
		t.Fatalf("problem = %#v", body)
	}
}

func TestModuleRequestResetNotConfigured(t *testing.T) {
	router := resetTestRouter(t, New(Deps{}), httpapi.Middlewares{})

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/reset-password/request", map[string]any{
		"username": "celeste",
	}))

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
}

func TestModuleRequestResetRateLimitRunsBeforeRequester(t *testing.T) {
	called := false
	mw := httpapi.Middlewares{
		RateLimit: func(...ratelimit.MiddlewareOption) gin.HandlerFunc {
			return func(c *gin.Context) {
				called = true
				c.AbortWithStatus(http.StatusTooManyRequests)
			}
		},
	}
	router := resetTestRouter(t, New(Deps{Requester: &requester{}}), mw)

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodPost, "/auth/reset-password/request", map[string]any{
		"username": "celeste",
	}))

	if !called {
		t.Fatal("rate limit middleware was not called")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestModuleRequestResetMalformedJSONGetsGenericAcceptedResponse(t *testing.T) {
	router := resetTestRouter(t, New(Deps{Requester: &requester{}}), httpapi.Middlewares{})

	req := testutil.NewJSONRequest(t, http.MethodPost, "/auth/reset-password/request", nil)
	req.Body = io.NopCloser(strings.NewReader(`{"username":`))
	rec := testutil.Record(router, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	var body httpx.Problem
	testutil.DecodeJSON(t, rec.Body, &body)
	if body.Code != "reset_request_accepted" {
		t.Fatalf("problem = %#v", body)
	}
}

func resetTestRouter(t testing.TB, module *Module, mw httpapi.Middlewares) *gin.Engine {
	t.Helper()
	testutil.SetGinTestMode(t)

	router := gin.New()
	router.Use(middleware.RequestIDMiddleware())
	module.RegisterRoutes(router.Group("/auth/reset-password"), mw)
	return router
}

func errorName(err error) string {
	if err == nil {
		return "success"
	}
	return err.Error()
}

type requester struct {
	req RequestResetRequest
	err error
}

func (r *requester) RequestReset(_ context.Context, req RequestResetRequest) (RequestResetResult, error) {
	r.req = req
	return RequestResetResult{}, r.err
}
