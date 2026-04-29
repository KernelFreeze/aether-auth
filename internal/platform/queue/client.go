package queue

import (
	"context"
	"errors"
	"fmt"

	"github.com/hibiken/asynq"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

// Task type identifiers used across the API and worker. Keep this list as
// the single source of truth.
const (
	TypeEmailSend      = "email:send"
	TypeAuditShip      = "audit:ship"
	TypeKeyRotation    = "keys:rotate"
	TypeExpiredCleanup = "cleanup:expired"
)

// NewClient constructs an Asynq client connected to the configured Redis.
func NewClient(ctx context.Context, cfg config.QueueConfig, sec secrets.Provider) (*asynq.Client, error) {
	opt, err := redisOpt(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	return asynq.NewClient(opt), nil
}

// NewServer constructs an Asynq server (worker) with the configured
// concurrency and the OWASP-recommended priority lanes.
func NewServer(ctx context.Context, cfg config.QueueConfig, sec secrets.Provider) (*asynq.Server, error) {
	opt, err := redisOpt(ctx, cfg, sec)
	if err != nil {
		return nil, err
	}
	srv := asynq.NewServer(opt, asynq.Config{
		Concurrency: cfg.Concurrency,
		Queues: map[string]int{
			"critical": 6,
			"default":  3,
			"low":      1,
		},
	})
	return srv, nil
}

func redisOpt(ctx context.Context, cfg config.QueueConfig, sec secrets.Provider) (asynq.RedisClientOpt, error) {
	var password string
	pw, err := sec.Resolve(ctx, cfg.PasswordRef)
	switch {
	case err == nil:
		password = string(pw)
	case errors.Is(err, secrets.ErrNotFound):
		password = ""
	default:
		return asynq.RedisClientOpt{}, fmt.Errorf("queue: resolve redis password: %w", err)
	}
	return asynq.RedisClientOpt{
		Addr:     cfg.RedisAddr,
		Password: password,
		DB:       cfg.DB,
	}, nil
}
