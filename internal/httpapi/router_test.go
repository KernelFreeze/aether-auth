package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
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

func TestNewRouterServesPasetoPublicKeys(t *testing.T) {
	testutil.SetGinTestMode(t)

	router := httpapi.NewRouter(httpapi.Deps{
		Config: testutil.Config(),
		Logger: testutil.Logger(t),
		PASETOKeys: keySource{keys: []paseto.PublicKey{
			{
				KeyID:  "kid-1",
				Key:    []byte("12345678901234567890123456789012"),
				Active: true,
			},
		}},
	})

	rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, "/.well-known/paseto-keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Keys []struct {
			KeyID         string `json:"kid"`
			PASETOVersion string `json:"paseto_version"`
			Status        string `json:"status"`
		} `json:"keys"`
	}
	testutil.DecodeJSON(t, rec.Body, &body)
	if len(body.Keys) != 1 {
		t.Fatalf("keys length = %d, want 1", len(body.Keys))
	}
	if body.Keys[0].KeyID != "kid-1" || body.Keys[0].PASETOVersion != "v4.public" || body.Keys[0].Status != "active" {
		t.Fatalf("key = %#v, want active v4.public kid-1", body.Keys[0])
	}
}

func TestNewRouterMountsFeatureModulesOnCentralPrefixes(t *testing.T) {
	testutil.SetGinTestMode(t)

	router := httpapi.NewRouter(httpapi.Deps{
		Config: testutil.Config(),
		Logger: testutil.Logger(t),
		Modules: httpapi.FeatureModules{
			Account:       probeModule{name: "account"},
			Auth:          probeModule{name: "auth"},
			MFA:           probeModule{name: "mfa"},
			OAuth:         probeModule{name: "oauth"},
			Organization:  probeModule{name: "org"},
			PasswordReset: probeModule{name: "password-reset"},
			Session:       probeModule{name: "session"},
		},
	})

	tests := map[string]string{
		"/account/probe":             "account",
		"/auth/probe":                "auth",
		"/auth/mfa/probe":            "mfa",
		"/oauth/probe":               "oauth",
		"/org/probe":                 "org",
		"/auth/reset-password/probe": "password-reset",
		"/session/probe":             "session",
	}

	for path, want := range tests {
		t.Run(path, func(t *testing.T) {
			rec := testutil.Record(router, testutil.NewJSONRequest(t, http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			var body map[string]string
			testutil.DecodeJSON(t, rec.Body, &body)
			if got := body["module"]; got != want {
				t.Fatalf("module = %q, want %q", got, want)
			}
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

type probeModule struct {
	name string
}

func (m probeModule) RegisterRoutes(r gin.IRouter, _ httpapi.Middlewares) {
	r.GET("/probe", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"module": m.name})
	})
}

type keySource struct {
	keys []paseto.PublicKey
}

func (s keySource) PublicKeys() []paseto.PublicKey {
	return s.keys
}
