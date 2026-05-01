package workers

import (
	"context"
	"errors"

	"github.com/hibiken/asynq"
	"go.uber.org/zap"

	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
)

var ErrKeyRotationNotConfigured = errors.New("workers: key rotation keystore not configured")

// HandleKeyRotation reloads PASETO key material from the configured secrets
// provider. Old public keys stay available until the keystore overlap window
// expires.
func HandleKeyRotation(keystore *paseto.Keystore, log *zap.Logger) asynq.HandlerFunc {
	return func(ctx context.Context, _ *asynq.Task) error {
		if keystore == nil {
			return ErrKeyRotationNotConfigured
		}
		if err := keystore.Reload(ctx); err != nil {
			return err
		}
		if log != nil {
			log.Info("paseto_keys_reloaded")
		}
		return nil
	}
}
