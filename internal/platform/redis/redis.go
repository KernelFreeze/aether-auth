// Package redis owns the project's redis client used for rate limiting, the
// token revocation set, and breach-corpus response caching.
package redis

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

// Open returns a connected redis client, having issued a PING to confirm
// reachability. The password is resolved through the secrets provider; an
// empty value is treated as "no auth".
func Open(ctx context.Context, cfg config.RedisConfig, sec secrets.Provider) (*redis.Client, error) {
	var password string
	pw, err := sec.Resolve(ctx, cfg.PasswordRef)
	switch {
	case err == nil:
		password = string(pw)
	case errors.Is(err, secrets.ErrNotFound):
		password = ""
	default:
		return nil, fmt.Errorf("redis: resolve password: %w", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: password,
		DB:       cfg.DB,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return client, nil
}
