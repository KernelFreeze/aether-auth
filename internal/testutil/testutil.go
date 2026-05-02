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
	"strings"
	"sync"
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

// FakeClock is a manually advanced clock for deterministic tests.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a clock fixed at now until Set or Advance is called.
func NewFakeClock(now time.Time) *FakeClock {
	return &FakeClock{now: now}
}

// Now returns the clock's current instant.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Set moves the clock to now.
func (c *FakeClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = now
}

// Advance moves the clock by d and returns the new instant.
func (c *FakeClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
	return c.now
}

// DeterministicReader repeats a fixed byte sequence for random-reader tests.
type DeterministicReader struct {
	mu     sync.Mutex
	seed   []byte
	offset int
}

// NewDeterministicReader returns an io.Reader that repeats seed forever.
func NewDeterministicReader(seed []byte) *DeterministicReader {
	if len(seed) == 0 {
		seed = []byte{0}
	}

	return &DeterministicReader{seed: append([]byte(nil), seed...)}
}

// Read fills p from the deterministic byte stream.
func (r *DeterministicReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range p {
		p[i] = r.seed[r.offset%len(r.seed)]
		r.offset++
	}
	return len(p), nil
}

// ConfigBuilder builds test config values without touching process
// environment or real secret values.
type ConfigBuilder struct {
	cfg config.Config
}

// NewConfigBuilder returns a builder loaded with test-safe defaults.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{cfg: baseConfig()}
}

// With applies mutate to the builder's config and returns the same builder.
func (b *ConfigBuilder) With(mutate func(*config.Config)) *ConfigBuilder {
	if mutate != nil {
		mutate(&b.cfg)
	}
	return b
}

// Build returns an independent copy of the configured test config.
func (b *ConfigBuilder) Build() *config.Config {
	return cloneConfig(b.cfg)
}

// Config returns a project config suitable for unit tests.
func Config() *config.Config {
	return NewConfigBuilder().Build()
}

func baseConfig() config.Config {
	return config.Config{
		Server: config.ServerConfig{
			Port:            "0",
			Env:             "test",
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: time.Second,
		},
		Postgres: config.PostgresConfig{
			Host:        "localhost",
			Port:        "5432",
			User:        "aether",
			PasswordRef: "env://DB_PASSWORD",
			Name:        "aether_auth_test",
			SSLMode:     "disable",
			MaxConns:    4,
			MinConns:    0,
			MaxConnLife: time.Hour,
		},
		Redis: config.RedisConfig{
			Addr:        "localhost:6379",
			PasswordRef: "env://REDIS_PASSWORD",
			DB:          15,
		},
		Mailer: config.MailerConfig{
			Host:        "localhost",
			Port:        1025,
			PasswordRef: "env://SMTP_PASSWORD",
			From:        "noreply@example.test",
		},
		Queue: config.QueueConfig{
			RedisAddr:   "localhost:6379",
			PasswordRef: "env://QUEUE_REDIS_PASSWORD",
			DB:          14,
			Concurrency: 1,
		},
		Issuer: config.IssuerConfig{
			URL:       "https://auth.example.test",
			BaseURL:   "https://auth.example.test",
			Audiences: []string{"https://api.example.test"},
		},
		Secrets: config.SecretsConfig{
			Pepper:           "env://AUTH_PEPPER",
			AESKey:           "env://AUTH_AES_KEY",
			PASETOLocalKey:   "env://AUTH_PASETO_LOCAL_KEY",
			PASETOPublicSeed: "env://AUTH_PASETO_SEED",
			CSRFSecret:       "env://AUTH_CSRF_SECRET",
		},
		Argon2: config.Argon2Config{
			Memory:      64,
			Iterations:  1,
			Parallelism: 1,
			SaltLength:  16,
			KeyLength:   32,
		},
		Session: config.SessionConfig{
			AccessTTL:          15 * time.Minute,
			RefreshSliding:     30 * 24 * time.Hour,
			RefreshAbsolute:    90 * 24 * time.Hour,
			PartialSessionTTL:  2 * time.Minute,
			RevocationCacheTTL: 15 * time.Minute,
		},
		PASETO: config.PASETOConfig{
			RotationInterval: 90 * 24 * time.Hour,
			OverlapWindow:    14 * 24 * time.Hour,
		},
		OAuth: config.OAuthServerConfig{
			CodeTTL:             time.Minute,
			AccessTTL:           15 * time.Minute,
			RefreshTTL:          30 * 24 * time.Hour,
			RotateRefreshTokens: true,
			DefaultScopes:       []string{"openid", "profile"},
			RequirePKCE:         true,
		},
		OIDC: config.OIDCConfig{
			EnabledProviders: []string{},
		},
		RateLimits: config.RateLimitConfig{
			PerIPPerMinute:      100,
			PerAccountPerMinute: 10,
			ResetPerMinute:      5,
		},
		Lockout: config.LockoutConfig{
			FailuresBeforeLockout: 5,
			BackoffSchedule:       []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour},
			CaptchaAfterFailures:  3,
		},
		PasswordReset: config.PasswordResetConfig{
			TokenTTL: 20 * time.Minute,
		},
		HIBP: config.HIBPConfig{
			Enabled:  true,
			BaseURL:  "https://api.pwnedpasswords.com",
			CacheTTL: 24 * time.Hour,
		},
		CSRF: config.CSRFConfig{
			CookieName: "XSRF-TOKEN",
			HeaderName: "X-XSRF-TOKEN",
		},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type", "X-XSRF-TOKEN"},
		},
		Audit: config.AuditConfig{
			Sink: "db",
		},
		Logging: config.LoggingConfig{
			Development: true,
			Level:       "debug",
		},
		Org: config.OrgConfig{
			DefaultRole:   "member",
			InvitationTTL: 7 * 24 * time.Hour,
		},
	}
}

func cloneConfig(c config.Config) *config.Config {
	c.Issuer.Audiences = append([]string(nil), c.Issuer.Audiences...)
	c.OAuth.DefaultScopes = append([]string(nil), c.OAuth.DefaultScopes...)
	c.OIDC.EnabledProviders = append([]string(nil), c.OIDC.EnabledProviders...)
	c.Lockout.BackoffSchedule = append([]time.Duration(nil), c.Lockout.BackoffSchedule...)
	c.CORS.AllowedOrigins = append([]string(nil), c.CORS.AllowedOrigins...)
	c.CORS.AllowedMethods = append([]string(nil), c.CORS.AllowedMethods...)
	c.CORS.AllowedHeaders = append([]string(nil), c.CORS.AllowedHeaders...)
	return &c
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

// AssertJSONResponse checks status, JSON content type, and response body.
func AssertJSONResponse(t testing.TB, rec *httptest.ResponseRecorder, wantStatus int, wantBody any) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d", rec.Code, wantStatus)
	}

	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", contentType)
	}

	if wantBody == nil {
		return
	}

	gotJSON := canonicalJSON(t, rec.Body.Bytes())
	wantJSON := mustMarshalJSON(t, wantBody)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("JSON body = %s, want %s", gotJSON, wantJSON)
	}
}

// DecodeJSON decodes a JSON response body into dst.
func DecodeJSON(t testing.TB, body io.Reader, dst any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
}

func canonicalJSON(t testing.TB, data []byte) []byte {
	t.Helper()

	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
	return mustMarshalJSON(t, v)
}

func mustMarshalJSON(t testing.TB, v any) []byte {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return data
}
