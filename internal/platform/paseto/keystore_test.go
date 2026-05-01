package paseto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gopaseto "aidanwoods.dev/go-paseto"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestNewKeystoreLoadsKeys(t *testing.T) {
	sec := testutil.StaticSecrets{
		"env://LOCAL": bytes.Repeat([]byte{0x11}, 32),
		"env://SEED":  bytes.Repeat([]byte{0x22}, 32),
	}

	ks, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{
		OverlapWindow: time.Hour,
	}, sec, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}
	if ks == nil {
		t.Fatal("NewKeystore() = nil")
	}
	keys := ks.PublicKeys()
	if len(keys) != 1 {
		t.Fatalf("PublicKeys() length = %d, want 1", len(keys))
	}
	if keys[0].KeyID == "" {
		t.Fatal("PublicKeys()[0].KeyID is empty")
	}
	if len(keys[0].Key) != 32 {
		t.Fatalf("PublicKeys()[0].Key length = %d, want 32", len(keys[0].Key))
	}
}

func TestNewKeystoreAcceptsEncodedKeys(t *testing.T) {
	sec := testutil.StaticSecrets{
		"env://LOCAL": []byte(hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))),
		"env://SEED":  []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))),
	}

	if _, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, sec, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	}); err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}
}

func TestNewKeystoreResolveErrors(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x42}, 32)
	tests := []struct {
		name    string
		secrets testutil.StaticSecrets
		refs    paseto.Refs
		wantRef string
	}{
		{
			name: "missing local key",
			secrets: testutil.StaticSecrets{
				"env://SEED": validKey,
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
				"env://LOCAL": validKey,
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

func TestNewKeystoreRejectsInvalidKeyMaterial(t *testing.T) {
	tests := []struct {
		name    string
		secrets testutil.StaticSecrets
	}{
		{
			name: "local key too short",
			secrets: testutil.StaticSecrets{
				"env://LOCAL": []byte("short"),
				"env://SEED":  bytes.Repeat([]byte{0x22}, 32),
			},
		},
		{
			name: "public seed too short",
			secrets: testutil.StaticSecrets{
				"env://LOCAL": bytes.Repeat([]byte{0x11}, 32),
				"env://SEED":  []byte("short"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, tt.secrets, paseto.Refs{
				LocalKey:   "env://LOCAL",
				PublicSeed: "env://SEED",
			})
			if !errors.Is(err, paseto.ErrInvalidKeyMaterial) {
				t.Fatalf("NewKeystore() error = %v, want ErrInvalidKeyMaterial", err)
			}
		})
	}
}

func TestIssueAndVerifyAccessToken(t *testing.T) {
	ks := newTestKeystore(t)
	req := paseto.IssueRequest{
		Claims: map[string]any{
			"sub":   "acct-1",
			"scope": "profile:read",
			"exp":   time.Now().Add(time.Hour),
		},
		Implicit: []byte("client-1"),
	}

	raw, err := ks.IssueAccessToken(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAccessToken() error = %v", err)
	}
	assertFooterHasKID(t, raw, gopaseto.V4Public)

	token, err := ks.VerifyAccessToken(context.Background(), raw, []byte("client-1"), gopaseto.Subject("acct-1"))
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if got, err := token.GetSubject(); err != nil || got != "acct-1" {
		t.Fatalf("GetSubject() = %q, %v; want acct-1, nil", got, err)
	}

	if _, err := ks.VerifyAccessToken(context.Background(), raw, []byte("client-2")); err == nil {
		t.Fatal("VerifyAccessToken() with wrong implicit assertion error = nil, want error")
	}
}

func TestIssueAndVerifyPartialSessionToken(t *testing.T) {
	ks := newTestKeystore(t)
	req := paseto.IssueRequest{
		Claims: map[string]any{
			"sub": "acct-1",
			"mfa": "pending",
			"exp": time.Now().Add(time.Minute),
		},
		Implicit: []byte("mfa-flow-1"),
	}

	raw, err := ks.IssuePartialSessionToken(context.Background(), req)
	if err != nil {
		t.Fatalf("IssuePartialSessionToken() error = %v", err)
	}
	assertFooterHasKID(t, raw, gopaseto.V4Local)

	token, err := ks.VerifyPartialSessionToken(context.Background(), raw, []byte("mfa-flow-1"))
	if err != nil {
		t.Fatalf("VerifyPartialSessionToken() error = %v", err)
	}
	var mfa string
	if err := token.Get("mfa", &mfa); err != nil || mfa != "pending" {
		t.Fatalf("mfa claim = %q, %v; want pending, nil", mfa, err)
	}

	if _, err := ks.VerifyPartialSessionToken(context.Background(), raw, []byte("other-flow")); err == nil {
		t.Fatal("VerifyPartialSessionToken() with wrong implicit assertion error = nil, want error")
	}
}

func TestReloadRetainsPreviousPublicVerificationKeys(t *testing.T) {
	sec := testutil.StaticSecrets{
		"env://LOCAL": bytes.Repeat([]byte{0x11}, 32),
		"env://SEED":  bytes.Repeat([]byte{0x22}, 32),
	}
	ks, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, sec, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}

	oldToken, err := ks.IssueAccessToken(context.Background(), paseto.IssueRequest{
		Claims: map[string]any{
			"sub": "acct-old",
			"exp": time.Now().Add(time.Hour),
		},
	})
	if err != nil {
		t.Fatalf("IssueAccessToken() old error = %v", err)
	}

	sec["env://LOCAL"] = bytes.Repeat([]byte{0x33}, 32)
	sec["env://SEED"] = bytes.Repeat([]byte{0x44}, 32)
	if err := ks.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	if _, err := ks.VerifyAccessToken(context.Background(), oldToken, nil, gopaseto.Subject("acct-old")); err != nil {
		t.Fatalf("VerifyAccessToken() old token after reload error = %v", err)
	}
	if keys := ks.PublicKeys(); len(keys) != 2 {
		t.Fatalf("PublicKeys() length after reload = %d, want 2", len(keys))
	}
}

func newTestKeystore(t *testing.T) *paseto.Keystore {
	t.Helper()
	ks, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{}, testutil.StaticSecrets{
		"env://LOCAL": bytes.Repeat([]byte{0x11}, 32),
		"env://SEED":  bytes.Repeat([]byte{0x22}, 32),
	}, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}
	return ks
}

func assertFooterHasKID(t *testing.T, raw string, protocol gopaseto.Protocol) {
	t.Helper()
	footerBytes, err := gopaseto.NewParserWithoutExpiryCheck().UnsafeParseFooter(protocol, raw)
	if err != nil {
		t.Fatalf("UnsafeParseFooter() error = %v", err)
	}
	var footer struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(footerBytes, &footer); err != nil {
		t.Fatalf("footer JSON error = %v", err)
	}
	if footer.KeyID == "" {
		t.Fatal("footer kid is empty")
	}
}
