package password

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/auth"
)

func TestHIBPCheckerUsesKAnonymityRangeAndCache(t *testing.T) {
	prefix, suffix := passwordRangeParts("correct horse battery staple")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/range/"+prefix {
			t.Fatalf("path = %q, want /range/%s", r.URL.Path, prefix)
		}
		if r.Header.Get("Add-Padding") != "true" {
			t.Fatalf("Add-Padding = %q, want true", r.Header.Get("Add-Padding"))
		}
		_, _ = w.Write([]byte(suffix + ":42\r\nABCDEF:1\r\n"))
	}))
	defer server.Close()

	cache := &memoryHIBPCache{}
	checker := &HIBPChecker{
		Enabled:  true,
		BaseURL:  server.URL,
		CacheTTL: time.Hour,
		Cache:    cache,
	}

	first, err := checker.CheckPasswordBreach(context.Background(), auth.PasswordBreachRequest{Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("check breach: %v", err)
	}
	second, err := checker.CheckPasswordBreach(context.Background(), auth.PasswordBreachRequest{Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("check cached breach: %v", err)
	}

	if !first.Breached || first.Count != 42 || !second.Breached || requests != 1 {
		t.Fatalf("results = %#v %#v requests=%d", first, second, requests)
	}
	if cache.prefix != prefix || cache.ttl != time.Hour {
		t.Fatalf("cache = %#v", cache)
	}
}

type memoryHIBPCache struct {
	prefix string
	body   string
	ttl    time.Duration
}

func (c *memoryHIBPCache) GetPasswordRange(_ context.Context, prefix string) (string, bool, error) {
	if c.prefix == prefix && c.body != "" {
		return c.body, true, nil
	}
	return "", false, nil
}

func (c *memoryHIBPCache) SetPasswordRange(_ context.Context, prefix, body string, ttl time.Duration) error {
	c.prefix = prefix
	c.body = body
	c.ttl = ttl
	return nil
}
