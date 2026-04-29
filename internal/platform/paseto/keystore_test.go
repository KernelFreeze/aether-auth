package paseto_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestNewKeystoreResolvesRequiredRefs(t *testing.T) {
	sec := testutil.StaticSecrets{
		"env://LOCAL": []byte("local-key"),
		"env://SEED":  []byte("public-seed"),
	}

	ks, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, sec, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}
	if ks == nil {
		t.Fatal("NewKeystore() = nil")
	}
}

func TestNewKeystoreResolveErrors(t *testing.T) {
	tests := []struct {
		name    string
		secrets testutil.StaticSecrets
		refs    paseto.Refs
		wantRef string
	}{
		{
			name: "missing local key",
			secrets: testutil.StaticSecrets{
				"env://SEED": []byte("public-seed"),
			},
			refs: paseto.Refs{
				LocalKey:   "env://LOCAL",
				PublicSeed: "env://SEED",
			},
			wantRef: "env://LOCAL",
		},
		{
			name: "missing public seed",
			secrets: testutil.StaticSecrets{
				"env://LOCAL": []byte("local-key"),
			},
			refs: paseto.Refs{
				LocalKey:   "env://LOCAL",
				PublicSeed: "env://SEED",
			},
			wantRef: "env://SEED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, tt.secrets, tt.refs)
			if err == nil {
				t.Fatal("NewKeystore() error = nil, want error")
			}
			if !errors.Is(err, secrets.ErrNotFound) {
				t.Fatalf("NewKeystore() error = %v, want ErrNotFound", err)
			}
			if !strings.Contains(err.Error(), tt.wantRef) {
				t.Fatalf("NewKeystore() error = %q, want ref %q", err, tt.wantRef)
			}
		})
	}
}

func TestKeystoreReloadIsStubbed(t *testing.T) {
	sec := testutil.StaticSecrets{
		"env://LOCAL": []byte("local-key"),
		"env://SEED":  []byte("public-seed"),
	}
	ks, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, sec, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}

	if err := ks.Reload(context.Background()); !errors.Is(err, paseto.ErrNotImplemented) {
		t.Fatalf("Reload() error = %v, want ErrNotImplemented", err)
	}
}
