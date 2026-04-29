// Package testutil contains small helpers shared by unit and integration tests.
package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

// StaticSecrets is an in-memory secrets.Provider for tests.
type StaticSecrets map[string][]byte

// Resolve returns a copy of the configured secret value.
func (s StaticSecrets) Resolve(_ context.Context, ref string) ([]byte, error) {
	v, ok := s[ref]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref)
	}
	return append([]byte(nil), v...), nil
}

// Config returns a minimal project config suitable for HTTP unit tests.
func Config() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:            "0",
			Env:             "test",
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: time.Second,
		},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type", "X-XSRF-TOKEN"},
		},
		PASETO: config.PASETOConfig{
			RotationInterval: 90 * 24 * time.Hour,
			OverlapWindow:    14 * 24 * time.Hour,
		},
	}
}

// Logger returns a zap test logger bound to the current test.
func Logger(t testing.TB) *zap.Logger {
	t.Helper()
	return zaptest.NewLogger(t)
}

// SetGinTestMode switches Gin into test mode for the duration of t.
func SetGinTestMode(t testing.TB) {
	t.Helper()
	previous := gin.Mode()
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() {
		gin.SetMode(previous)
	})
}

// NewJSONRequest builds an httptest request with a JSON body.
func NewJSONRequest(t testing.TB, method, target string, body any) *http.Request {
	t.Helper()

	var r io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request JSON: %v", err)
		}
		r = bytes.NewReader(payload)
	}

	req := httptest.NewRequest(method, target, r)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// Record serves a request and returns its response recorder.
func Record(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// DecodeJSON decodes a JSON response body into dst.
func DecodeJSON(t testing.TB, body io.Reader, dst any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
}
