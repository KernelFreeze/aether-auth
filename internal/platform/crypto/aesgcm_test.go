package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

func TestSealOpenCredentialPayloadRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	random := bytes.NewReader(bytes.Repeat([]byte{0x11}, 12))
	aad := []byte("credential:password")

	payload, err := crypto.SealCredentialPayload(key, []byte("secret credential data"), aad, random)
	if err != nil {
		t.Fatalf("SealCredentialPayload() error = %v", err)
	}
	if len(payload) <= len("secret credential data") {
		t.Fatalf("payload length = %d, want encrypted envelope", len(payload))
	}

	plaintext, err := crypto.OpenCredentialPayload(key, payload, aad)
	if err != nil {
		t.Fatalf("OpenCredentialPayload() error = %v", err)
	}
	if string(plaintext) != "secret credential data" {
		t.Fatalf("plaintext = %q, want original value", plaintext)
	}
}

func TestOpenCredentialPayloadRejectsInvalidInput(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	payload, err := crypto.SealCredentialPayload(key, []byte("secret"), []byte("aad"), bytes.NewReader(bytes.Repeat([]byte{0x11}, 12)))
	if err != nil {
		t.Fatalf("SealCredentialPayload() error = %v", err)
	}

	tests := []struct {
		name    string
		key     []byte
		payload []byte
		aad     []byte
		wantErr error
	}{
		{
			name:    "wrong key length",
			key:     []byte("short"),
			payload: payload,
			aad:     []byte("aad"),
			wantErr: crypto.ErrInvalidAESKey,
		},
		{
			name:    "wrong version",
			key:     key,
			payload: append([]byte{0xff}, payload[1:]...),
			aad:     []byte("aad"),
			wantErr: crypto.ErrInvalidCiphertext,
		},
		{
			name:    "wrong aad",
			key:     key,
			payload: payload,
			aad:     []byte("other"),
			wantErr: crypto.ErrInvalidCiphertext,
		},
		{
			name:    "truncated",
			key:     key,
			payload: payload[:10],
			aad:     []byte("aad"),
			wantErr: crypto.ErrInvalidCiphertext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.OpenCredentialPayload(tt.key, tt.payload, tt.aad)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("OpenCredentialPayload() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSealCredentialPayloadRejectsInvalidInput(t *testing.T) {
	if _, err := crypto.SealCredentialPayload([]byte("short"), []byte("secret"), nil, bytes.NewReader(nil)); !errors.Is(err, crypto.ErrInvalidAESKey) {
		t.Fatalf("SealCredentialPayload() error = %v, want ErrInvalidAESKey", err)
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	if _, err := crypto.SealCredentialPayload(key, []byte("secret"), nil, nil); err == nil {
		t.Fatal("SealCredentialPayload() error = nil, want error")
	}
}
