package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestRequestIDMiddlewareUsesIncomingID(t *testing.T) {
	rec := performRequestIDRequest(t, "req-123")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-123" {
		t.Fatalf("response request id = %q, want req-123", got)
	}
	if got := rec.Body.String(); got != "req-123" {
		t.Fatalf("handler request id = %q, want req-123", got)
	}
}

func TestRequestIDMiddlewareGeneratesMissingID(t *testing.T) {
	rec := performRequestIDRequest(t, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	id := rec.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("response request id is empty")
	}
	if got := rec.Body.String(); got != id {
		t.Fatalf("handler request id = %q, response header = %q", got, id)
	}
}

func performRequestIDRequest(t *testing.T, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.Use(middleware.RequestIDMiddleware())
	r.GET("/", func(c *gin.Context) {
		_, _ = c.Writer.WriteString(middleware.RequestID(c))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	return testutil.Record(r, req)
}
