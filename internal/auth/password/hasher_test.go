package password

import (
	"context"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestArgon2idHasherHashesVerifiesAndDetectsRehash(t *testing.T) {
	reader := testutil.NewDeterministicReader([]byte{0x7a})
	hasher := NewArgon2idHasher(config.Argon2Config{
		Memory:      64,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}, []byte("pepper"), reader)

	hash, err := hasher.HashPassword(context.Background(), auth.PasswordHashRequest{Password: "correct horse battery staple"})
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash.PHCString == "" || hash.ParamsID == "" {
		t.Fatalf("hash = %#v", hash)
	}

	verified, err := hasher.VerifyPassword(context.Background(), auth.PasswordVerifyRequest{
		Password: "correct horse battery staple",
		Hash:     hash,
	})
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !verified.Matched || verified.NeedsRehash {
		t.Fatalf("verify result = %#v, want match without rehash", verified)
	}

	stronger := NewArgon2idHasher(config.Argon2Config{
		Memory:      128,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}, []byte("pepper"), reader)
	verified, err = stronger.VerifyPassword(context.Background(), auth.PasswordVerifyRequest{
		Password: "correct horse battery staple",
		Hash:     hash,
	})
	if err != nil {
		t.Fatalf("verify stronger password: %v", err)
	}
	if !verified.Matched || !verified.NeedsRehash {
		t.Fatalf("stronger verify result = %#v, want match needing rehash", verified)
	}
}
