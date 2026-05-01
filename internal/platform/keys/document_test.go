package keys_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/platform/keys"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
)

func TestDiscoveryDocumentFormatsPasetoPublicKeys(t *testing.T) {
	retainUntil := time.Date(2026, 5, 1, 12, 0, 0, 0, time.FixedZone("test", -5*60*60))
	source := staticSource{
		keys: []paseto.PublicKey{
			{
				KeyID:  "active-kid",
				Key:    []byte("12345678901234567890123456789012"),
				Active: true,
			},
			{
				KeyID:       "retained-kid",
				Key:         []byte("abcdefghijklmnopqrstuvwxzy123456"),
				RetainUntil: retainUntil,
			},
		},
	}

	doc := keys.DiscoveryDocument(source)
	if len(doc.Keys) != 2 {
		t.Fatalf("keys length = %d, want 2", len(doc.Keys))
	}

	active := doc.Keys[0]
	if active.KeyID != "active-kid" {
		t.Fatalf("active kid = %q, want active-kid", active.KeyID)
	}
	if active.KeyType != "OKP" || active.Curve != "Ed25519" || active.Algorithm != "EdDSA" || active.Use != "sig" {
		t.Fatalf("active key metadata = %#v", active)
	}
	if active.PASETOVersion != keys.PASETOVersion {
		t.Fatalf("paseto version = %q, want %q", active.PASETOVersion, keys.PASETOVersion)
	}
	if active.Status != "active" {
		t.Fatalf("active status = %q, want active", active.Status)
	}
	if active.RetainUntil != nil {
		t.Fatalf("active retain_until = %v, want nil", active.RetainUntil)
	}
	if active.X != base64.RawURLEncoding.EncodeToString(source.keys[0].Key) {
		t.Fatalf("active x = %q, want base64url public key", active.X)
	}

	retained := doc.Keys[1]
	if retained.Status != "retained" {
		t.Fatalf("retained status = %q, want retained", retained.Status)
	}
	if retained.RetainUntil == nil || !retained.RetainUntil.Equal(retainUntil.UTC()) {
		t.Fatalf("retained retain_until = %v, want %v", retained.RetainUntil, retainUntil.UTC())
	}
}

func TestDiscoveryDocumentHandlesNilSource(t *testing.T) {
	doc := keys.DiscoveryDocument(nil)
	if doc.Keys == nil {
		t.Fatal("keys = nil, want empty slice")
	}
	if len(doc.Keys) != 0 {
		t.Fatalf("keys length = %d, want 0", len(doc.Keys))
	}
}

type staticSource struct {
	keys []paseto.PublicKey
}

func (s staticSource) PublicKeys() []paseto.PublicKey {
	return s.keys
}
