package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestRecoverTurnsPanicIntoInternalError(t *testing.T) {
	testutil.SetGinTestMode(t)

	r := gin.New()
	r.Use(middleware.RequestIDMiddleware(), middleware.Recover(testutil.Logger(t)))
	r.GET("/panic", func(_ *gin.Context) {
		panic("boom")
	})

	rec := testutil.Record(r, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	var body map[string]string
	testutil.DecodeJSON(t, rec.Body, &body)
	if body["error"] != "internal_error" {
		t.Fatalf("error = %q, want internal_error", body["error"])
	}
}
