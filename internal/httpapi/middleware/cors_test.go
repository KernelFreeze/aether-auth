package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestCORSWildcardOrigin(t *testing.T) {
	cfg := corsConfig([]string{"*"})
	rec := performCORSRequest(t, cfg, http.MethodGet, "https://app.example.com")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want empty", got)
	}
}

func TestCORSAllowedOrigin(t *testing.T) {
	cfg := corsConfig([]string{"https://app.example.com"})
	rec := performCORSRequest(t, cfg, http.MethodGet, "https://app.example.com")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}

func TestCORSRejectsUnknownOrigin(t *testing.T) {
	cfg := corsConfig([]string{"https://app.example.com"})
	rec := performCORSRequest(t, cfg, http.MethodGet, "https://evil.example.com")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestCORSPreflightAborts(t *testing.T) {
	cfg := corsConfig([]string{"https://app.example.com"})
	rec := performCORSRequest(t, cfg, http.MethodOptions, "https://app.example.com")

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Fatalf("Access-Control-Allow-Methods = %q", got)
	}
}

func corsConfig(origins []string) config.CORSConfig {
	return config.CORSConfig{
		AllowedOrigins: origins,
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}
}

func performCORSRequest(t *testing.T, cfg config.CORSConfig, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.Use(middleware.CORS(cfg))
	r.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.OPTIONS("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(method, "/", nil)
	req.Header.Set("Origin", origin)
	return testutil.Record(r, req)
}
