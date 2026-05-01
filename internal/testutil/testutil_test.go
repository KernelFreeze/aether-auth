package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
)

func TestFakeClockCanBeSetAndAdvanced(t *testing.T) {
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)

	if got := clock.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, want %v", got, start)
	}

	next := clock.Advance(2 * time.Minute)
	if want := start.Add(2 * time.Minute); !next.Equal(want) || !clock.Now().Equal(want) {
		t.Fatalf("Advance() = %v and Now() = %v, want %v", next, clock.Now(), want)
	}

	reset := start.Add(-time.Hour)
	clock.Set(reset)
	if got := clock.Now(); !got.Equal(reset) {
		t.Fatalf("Now() after Set() = %v, want %v", got, reset)
	}
}

func TestDeterministicReaderRepeatsSeed(t *testing.T) {
	reader := NewDeterministicReader([]byte{1, 2, 3})
	got := make([]byte, 8)

	n, err := reader.Read(got)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != len(got) {
		t.Fatalf("Read() n = %d, want %d", n, len(got))
	}

	want := []byte{1, 2, 3, 1, 2, 3, 1, 2}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = %d, want %d; full buffer %v", i, got[i], want[i], got)
		}
	}
}

func TestConfigBuilderReturnsIndependentCopies(t *testing.T) {
	builder := NewConfigBuilder().With(func(cfg *config.Config) {
		cfg.Server.Port = "8181"
		cfg.CORS.AllowedOrigins = []string{"https://app.example.test"}
	})

	first := builder.Build()
	first.CORS.AllowedOrigins[0] = "https://mutated.example.test"
	second := builder.Build()

	if first.Server.Port != "8181" || second.Server.Port != "8181" {
		t.Fatalf("server ports = %q/%q, want both 8181", first.Server.Port, second.Server.Port)
	}
	if got := second.CORS.AllowedOrigins[0]; got != "https://app.example.test" {
		t.Fatalf("builder slice leaked mutation: %q", got)
	}
	if cfg := Config(); cfg.Server.Env != "test" {
		t.Fatalf("Config().Server.Env = %q, want test", cfg.Server.Env)
	}
}

func TestAssertJSONResponseChecksStatusContentTypeAndBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true,"count":1}`))
	})

	rec := Record(handler, httptest.NewRequest(http.MethodPost, "/json", nil))
	AssertJSONResponse(t, rec, http.StatusCreated, map[string]any{
		"count": 1,
		"ok":    true,
	})
}
