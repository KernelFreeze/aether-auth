package httpx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestWriteProblemUsesProblemJSON(t *testing.T) {
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.GET("/login", func(c *gin.Context) {
		httpx.WriteProblem(c, httpx.Problem{
			Type:    "https://aether-auth.local/problems/invalid-credentials",
			Title:   "Invalid credentials",
			Status:  http.StatusUnauthorized,
			Code:    "invalid_credentials",
			Detail:  "The username or password is incorrect.",
			ErrorID: "AUTH-LOGIN-0001",
		})
	})

	rec := testutil.Record(r, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, httpx.ProblemMediaType) {
		t.Fatalf("Content-Type = %q, want prefix %q", got, httpx.ProblemMediaType)
	}

	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["type"] != "https://aether-auth.local/problems/invalid-credentials" {
		t.Fatalf("type = %q, want invalid credentials problem", body["type"])
	}
	if body["title"] != "Invalid credentials" {
		t.Fatalf("title = %q, want Invalid credentials", body["title"])
	}
	if body["status"] != float64(http.StatusUnauthorized) {
		t.Fatalf("status body = %#v, want %d", body["status"], http.StatusUnauthorized)
	}
	if body["code"] != "invalid_credentials" {
		t.Fatalf("code = %q, want invalid_credentials", body["code"])
	}
	if body["error_id"] != "AUTH-LOGIN-0001" {
		t.Fatalf("error_id = %q, want AUTH-LOGIN-0001", body["error_id"])
	}
}

func TestWriteProblemFillsDefaults(t *testing.T) {
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.GET("/problem", func(c *gin.Context) {
		httpx.WriteProblem(c, httpx.Problem{})
	})

	rec := testutil.Record(r, httptest.NewRequest(http.MethodGet, "/problem", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["type"] != "about:blank" {
		t.Fatalf("type = %q, want about:blank", body["type"])
	}
	if body["title"] != http.StatusText(http.StatusInternalServerError) {
		t.Fatalf("title = %q, want %q", body["title"], http.StatusText(http.StatusInternalServerError))
	}
	if body["status"] != float64(http.StatusInternalServerError) {
		t.Fatalf("status body = %#v, want %d", body["status"], http.StatusInternalServerError)
	}
}

func TestWriteAuthFailureUsesGenericLoginProblem(t *testing.T) {
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.GET("/login", httpx.WriteAuthFailure)

	rec := testutil.Record(r, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["type"] != httpx.ProblemTypeInvalidCredentials {
		t.Fatalf("type = %q, want %q", body["type"], httpx.ProblemTypeInvalidCredentials)
	}
	if body["code"] != "invalid_credentials" {
		t.Fatalf("code = %q, want invalid_credentials", body["code"])
	}
	if body["error_id"] != httpx.ErrorIDLoginGeneric {
		t.Fatalf("error_id = %q, want %q", body["error_id"], httpx.ErrorIDLoginGeneric)
	}
}

func TestWritePasswordResetAcceptedUsesGenericResetProblem(t *testing.T) {
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.POST("/reset", httpx.WritePasswordResetAccepted)

	rec := testutil.Record(r, httptest.NewRequest(http.MethodPost, "/reset", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}

	var body map[string]any
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["type"] != httpx.ProblemTypeResetRequestAccepted {
		t.Fatalf("type = %q, want %q", body["type"], httpx.ProblemTypeResetRequestAccepted)
	}
	if body["code"] != "reset_request_accepted" {
		t.Fatalf("code = %q, want reset_request_accepted", body["code"])
	}
	if body["error_id"] != httpx.ErrorIDPasswordReset {
		t.Fatalf("error_id = %q, want %q", body["error_id"], httpx.ErrorIDPasswordReset)
	}
}

func TestTimingEqualizerSleepsOnlyRemainingDuration(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var slept time.Duration

	equalizer := httpx.TimingEqualizer{
		MinDuration: 100 * time.Millisecond,
		Now: func() time.Time {
			return now
		},
		Sleep: func(_ context.Context, d time.Duration) error {
			slept = d
			return nil
		},
	}

	started := now.Add(-40 * time.Millisecond)
	if err := equalizer.Wait(context.Background(), started); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if slept != 60*time.Millisecond {
		t.Fatalf("slept = %s, want 60ms", slept)
	}
}

func TestTimingEqualizerDoesNotSleepAfterFloor(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	called := false

	equalizer := httpx.TimingEqualizer{
		MinDuration: 100 * time.Millisecond,
		Now: func() time.Time {
			return now
		},
		Sleep: func(_ context.Context, _ time.Duration) error {
			called = true
			return nil
		},
	}

	started := now.Add(-125 * time.Millisecond)
	if err := equalizer.Wait(context.Background(), started); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if called {
		t.Fatalf("Sleep was called after minimum duration elapsed")
	}
}

func TestTimingEqualizerReturnsSleepError(t *testing.T) {
	want := errors.New("context canceled")
	equalizer := httpx.TimingEqualizer{
		MinDuration: time.Second,
		Now: func() time.Time {
			return time.Unix(100, 0)
		},
		Sleep: func(_ context.Context, _ time.Duration) error {
			return want
		},
	}

	err := equalizer.Wait(context.Background(), time.Unix(99, int64(500*time.Millisecond)))
	if !errors.Is(err, want) {
		t.Fatalf("Wait() error = %v, want %v", err, want)
	}
}
