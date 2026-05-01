package password

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	platformcrypto "github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

// Argon2idHasher hashes passwords with HMAC peppering before Argon2id.
type Argon2idHasher struct {
	Params platformcrypto.Argon2idParams
	Pepper []byte
	Random io.Reader
}

var _ auth.PasswordHasher = (*Argon2idHasher)(nil)

// NewArgon2idHasher builds a password hasher from runtime config.
func NewArgon2idHasher(cfg config.Argon2Config, pepper []byte, random io.Reader) *Argon2idHasher {
	return &Argon2idHasher{
		Params: Argon2idParamsFromConfig(cfg),
		Pepper: append([]byte(nil), pepper...),
		Random: random,
	}
}

// Argon2idParamsFromConfig converts runtime config to crypto parameters.
func Argon2idParamsFromConfig(cfg config.Argon2Config) platformcrypto.Argon2idParams {
	return platformcrypto.Argon2idParams{
		Memory:      cfg.Memory,
		Iterations:  cfg.Iterations,
		Parallelism: cfg.Parallelism,
		SaltLength:  cfg.SaltLength,
		KeyLength:   cfg.KeyLength,
	}
}

// HashPassword returns an Argon2id PHC string.
func (h *Argon2idHasher) HashPassword(_ context.Context, req auth.PasswordHashRequest) (auth.PasswordHash, error) {
	if h == nil {
		return auth.PasswordHash{}, auth.NewServiceError(auth.ErrorKindInternal, "argon2id hasher is nil", nil)
	}
	encoded, err := platformcrypto.HashPassword([]byte(req.Password), h.Pepper, h.Params, h.random())
	if err != nil {
		return auth.PasswordHash{}, fmt.Errorf("argon2id hash password: %w", err)
	}
	return auth.PasswordHash{
		PHCString: encoded,
		ParamsID:  h.paramsID(),
	}, nil
}

// VerifyPassword compares a plaintext password with a stored PHC string.
func (h *Argon2idHasher) VerifyPassword(_ context.Context, req auth.PasswordVerifyRequest) (auth.PasswordVerifyResult, error) {
	if h == nil {
		return auth.PasswordVerifyResult{}, auth.NewServiceError(auth.ErrorKindInternal, "argon2id hasher is nil", nil)
	}
	matched, err := platformcrypto.VerifyPassword([]byte(req.Password), h.Pepper, req.Hash.PHCString)
	if err != nil {
		return auth.PasswordVerifyResult{}, err
	}
	needsRehash, err := platformcrypto.NeedsRehash(req.Hash.PHCString, h.Params)
	if err != nil {
		return auth.PasswordVerifyResult{}, err
	}
	return auth.PasswordVerifyResult{Matched: matched, NeedsRehash: needsRehash}, nil
}

func (h *Argon2idHasher) random() io.Reader {
	if h.Random != nil {
		return h.Random
	}
	return rand.Reader
}

func (h *Argon2idHasher) paramsID() string {
	return fmt.Sprintf("argon2id:m=%d,t=%d,p=%d,s=%d,k=%d", h.Params.Memory, h.Params.Iterations, h.Params.Parallelism, h.Params.SaltLength, h.Params.KeyLength)
}
