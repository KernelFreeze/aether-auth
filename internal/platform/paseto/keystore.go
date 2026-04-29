package paseto

import (
	"context"
	"errors"
	"sync"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

// ErrNotImplemented is returned by keystore methods until the cryptographic
// implementation lands. The keystore exists at scaffold time so the rest of
// the boot sequence (config, secrets resolution, route wiring) can take shape
// against a stable interface.
var ErrNotImplemented = errors.New("paseto: not implemented")

// Keystore exposes the active PASETO signing/encryption keys and the older
// verification keys retained during a rotation overlap window.
type Keystore struct {
	mu  sync.RWMutex
	cfg config.PASETOConfig
	sec secrets.Provider
}

// NewKeystore constructs an empty keystore. The actual key material will be
// loaded by Reload once the implementation lands; for now the constructor
// only validates that the secret references resolve.
func NewKeystore(ctx context.Context, cfg config.PASETOConfig, sec secrets.Provider, refs Refs) (*Keystore, error) {
	if _, err := sec.Resolve(ctx, refs.LocalKey); err != nil {
		return nil, err
	}
	if _, err := sec.Resolve(ctx, refs.PublicSeed); err != nil {
		return nil, err
	}
	return &Keystore{cfg: cfg, sec: sec}, nil
}

// Refs collects the secret URI references the keystore needs at boot.
type Refs struct {
	LocalKey   string
	PublicSeed string
}

// Reload rotates the active key set from the secrets provider. Wired up later
// alongside the v4.public/v4.local issuance helpers.
func (k *Keystore) Reload(_ context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return ErrNotImplemented
}
