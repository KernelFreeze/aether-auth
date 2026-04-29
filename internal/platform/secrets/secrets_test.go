package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEnvProviderResolve(t *testing.T) {
	t.Setenv("AETHER_SECRET", "secret-value")
	t.Setenv("AETHER_PATH_SECRET", "path-secret")

	tests := []struct {
		name string
		ref  string
		want string
	}{
		{
			name: "host form",
			ref:  "env://AETHER_SECRET",
			want: "secret-value",
		},
		{
			name: "path form",
			ref:  "env:///AETHER_PATH_SECRET",
			want: "path-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EnvProvider{}.Resolve(context.Background(), tt.ref)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("Resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnvProviderResolveErrors(t *testing.T) {
	t.Setenv("AETHER_EMPTY_SECRET", "")

	tests := []struct {
		name          string
		ref           string
		wantNotFound  bool
		wantSubstring string
	}{
		{
			name:         "missing env",
			ref:          "env://AETHER_MISSING_SECRET",
			wantNotFound: true,
		},
		{
			name:         "empty env",
			ref:          "env://AETHER_EMPTY_SECRET",
			wantNotFound: true,
		},
		{
			name:          "unsupported scheme",
			ref:           "vault://secret",
			wantSubstring: "unsupported scheme",
		},
		{
			name:          "empty name",
			ref:           "env://",
			wantSubstring: "empty variable name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EnvProvider{}.Resolve(context.Background(), tt.ref)
			if err == nil {
				t.Fatal("Resolve() error = nil, want error")
			}
			if tt.wantNotFound && !errors.Is(err, ErrNotFound) {
				t.Fatalf("Resolve() error = %v, want ErrNotFound", err)
			}
			if tt.wantSubstring != "" && !strings.Contains(err.Error(), tt.wantSubstring) {
				t.Fatalf("Resolve() error = %q, want substring %q", err, tt.wantSubstring)
			}
		})
	}
}

func TestMuxResolve(t *testing.T) {
	ctx := context.Background()
	mux := NewMux()
	mux.Register("static", providerFunc(func(_ context.Context, ref string) ([]byte, error) {
		return []byte("resolved:" + ref), nil
	}))

	got, err := mux.Resolve(ctx, "static://example")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if string(got) != "resolved:static://example" {
		t.Fatalf("Resolve() = %q", got)
	}

	if _, err := mux.Resolve(ctx, "not-a-uri"); err == nil || !strings.Contains(err.Error(), "not a URI reference") {
		t.Fatalf("Resolve() error = %v, want URI reference error", err)
	}
	if _, err := mux.Resolve(ctx, "vault://secret"); err == nil || !strings.Contains(err.Error(), "no backend") {
		t.Fatalf("Resolve() error = %v, want no backend error", err)
	}
}

type providerFunc func(context.Context, string) ([]byte, error)

func (f providerFunc) Resolve(ctx context.Context, ref string) ([]byte, error) {
	return f(ctx, ref)
}
