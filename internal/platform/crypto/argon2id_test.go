package crypto_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

func TestHashPasswordVerifyPasswordAndNeedsRehash(t *testing.T) {
	params := testArgon2idParams()
	salt := bytes.Repeat([]byte{0x7a}, int(params.SaltLength))

	encoded, err := crypto.HashPassword([]byte("correct horse battery staple"), []byte("pepper"), params, bytes.NewReader(salt))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("encoded hash = %q, want argon2id PHC string", encoded)
	}

	ok, err := crypto.VerifyPassword([]byte("correct horse battery staple"), []byte("pepper"), encoded)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword() = false, want true")
	}

	ok, err = crypto.VerifyPassword([]byte("wrong password"), []byte("pepper"), encoded)
	if err != nil {
		t.Fatalf("VerifyPassword() wrong password error = %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword() wrong password = true, want false")
	}

	needs, err := crypto.NeedsRehash(encoded, params)
	if err != nil {
		t.Fatalf("NeedsRehash() error = %v", err)
	}
	if needs {
		t.Fatal("NeedsRehash() = true, want false")
	}

	stronger := params
	stronger.Memory = 128
	needs, err = crypto.NeedsRehash(encoded, stronger)
	if err != nil {
		t.Fatalf("NeedsRehash() stronger error = %v", err)
	}
	if !needs {
		t.Fatal("NeedsRehash() stronger = false, want true")
	}
}

func TestPepperPasswordUsesHMACSHA256(t *testing.T) {
	first := crypto.PepperPassword([]byte("password"), []byte("pepper-a"))
	second := crypto.PepperPassword([]byte("password"), []byte("pepper-a"))
	otherPepper := crypto.PepperPassword([]byte("password"), []byte("pepper-b"))

	if len(first) != 32 {
		t.Fatalf("PepperPassword() length = %d, want 32", len(first))
	}
	if !bytes.Equal(first, second) {
		t.Fatal("PepperPassword() is not deterministic")
	}
	if bytes.Equal(first, otherPepper) {
		t.Fatal("PepperPassword() did not change with pepper")
	}
}

func TestParseArgon2idHashRejectsInvalidInput(t *testing.T) {
	valid, err := crypto.HashPassword([]byte("password"), []byte("pepper"), testArgon2idParams(), bytes.NewReader(bytes.Repeat([]byte{0x7a}, 16)))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "empty", encoded: ""},
		{name: "wrong algorithm", encoded: strings.Replace(valid, "argon2id", "argon2i", 1)},
		{name: "wrong version", encoded: strings.Replace(valid, "v=19", "v=16", 1)},
		{name: "missing parameter", encoded: strings.Replace(valid, ",p=1", "", 1)},
		{name: "duplicate parameter", encoded: strings.Replace(valid, "m=64,t=1,p=1", "m=64,m=64,t=1,p=1", 1)},
		{name: "bad salt", encoded: replacePHCPart(valid, 4, "not base64!")},
		{name: "bad key", encoded: replacePHCPart(valid, 5, "not base64!")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.ParseArgon2idHash(tt.encoded)
			if !errors.Is(err, crypto.ErrInvalidPHCString) {
				t.Fatalf("ParseArgon2idHash() error = %v, want ErrInvalidPHCString", err)
			}
		})
	}
}

func TestHashPasswordRejectsInvalidInput(t *testing.T) {
	params := testArgon2idParams()
	params.Memory = 0
	if _, err := crypto.HashPassword([]byte("password"), []byte("pepper"), params, bytes.NewReader(nil)); !errors.Is(err, crypto.ErrInvalidArgon2Params) {
		t.Fatalf("HashPassword() error = %v, want ErrInvalidArgon2Params", err)
	}

	if _, err := crypto.HashPassword([]byte("password"), []byte("pepper"), testArgon2idParams(), nil); err == nil {
		t.Fatal("HashPassword() error = nil, want error")
	}
}

func testArgon2idParams() crypto.Argon2idParams {
	return crypto.Argon2idParams{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func replacePHCPart(encoded string, index int, value string) string {
	parts := strings.Split(encoded, "$")
	parts[index] = value
	return strings.Join(parts, "$")
}
