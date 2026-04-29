package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestNewRouterServesScaffoldEndpoints(t *testing.T) {
	testutil.SetGinTestMode(t)

	router := httpapi.NewRouter(httpapi.Deps{
		Config: testutil.Config(),
		Logger: testutil.Logger(t),
	})

	tests := []struct {
		name      string
		path      string
		wantKey   string
		wantValue any
	}{
		{
			name:      "health",
			path:      "/healthz",
			wantKey:   "status",
			wantValue: "ok",
		},
		{
			name:      "paseto keys",
			path:      "/.well-known/paseto-keys",
			wantKey:   "keys",
			wantValue: []any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := testutil.NewJSONRequest(t, http.MethodGet, tt.path, nil)
			req.Header.Set("X-Request-Id", "req-router-test")
			rec := testutil.Record(router, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if got := rec.Header().Get("X-Request-Id"); got != "req-router-test" {
				t.Fatalf("X-Request-Id = %q, want req-router-test", got)
			}

			var body map[string]any
			testutil.DecodeJSON(t, rec.Body, &body)
			assertJSONValue(t, body[tt.wantKey], tt.wantValue)
		})
	}
}

func assertJSONValue(t *testing.T, got, want any) {
	t.Helper()
	switch want := want.(type) {
	case string:
		if got != want {
			t.Fatalf("JSON value = %#v, want %q", got, want)
		}
	case []any:
		values, ok := got.([]any)
		if !ok {
			t.Fatalf("JSON value = %#v, want []any", got)
		}
		if len(values) != len(want) {
			t.Fatalf("JSON array length = %d, want %d", len(values), len(want))
		}
	default:
		t.Fatalf("unsupported expected value type %T", want)
	}
}
