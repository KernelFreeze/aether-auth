package workers_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
	"github.com/KernelFreeze/aether-auth/internal/workers"
)

func TestHandleKeyRotationReloadsKeystore(t *testing.T) {
	sec := testutil.StaticSecrets{
		"env://LOCAL": bytes.Repeat([]byte{0x11}, 32),
		"env://SEED":  bytes.Repeat([]byte{0x22}, 32),
	}
	keystore, err := paseto.NewKeystore(context.Background(), config.PASETOConfig{
		OverlapWindow: time.Hour,
	}, sec, paseto.Refs{
		LocalKey:   "env://LOCAL",
		PublicSeed: "env://SEED",
	})
	if err != nil {
		t.Fatalf("NewKeystore() error = %v", err)
	}

	sec["env://LOCAL"] = bytes.Repeat([]byte{0x33}, 32)
	sec["env://SEED"] = bytes.Repeat([]byte{0x44}, 32)
	handler := workers.HandleKeyRotation(keystore, nil)

	if err := handler(context.Background(), asynq.NewTask("keys:rotate", nil)); err != nil {
		t.Fatalf("HandleKeyRotation() error = %v", err)
	}
	if keys := keystore.PublicKeys(); len(keys) != 2 {
		t.Fatalf("PublicKeys() length = %d, want 2", len(keys))
	}
}

func TestHandleKeyRotationRequiresKeystore(t *testing.T) {
	handler := workers.HandleKeyRotation(nil, nil)
	err := handler(context.Background(), asynq.NewTask("keys:rotate", nil))
	if !errors.Is(err, workers.ErrKeyRotationNotConfigured) {
		t.Fatalf("HandleKeyRotation() error = %v, want ErrKeyRotationNotConfigured", err)
	}
}
