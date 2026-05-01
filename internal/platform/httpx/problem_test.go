package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
