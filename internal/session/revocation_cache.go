package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const revokedAccessTokenKeyPrefix = "aether:session:revoked_access:"

// RedisRevocationCache stores revoked access-token IDs in Redis.
type RedisRevocationCache struct {
	client redis.Cmdable
}

// NewRedisRevocationCache builds a Redis-backed access-token revocation cache.
func NewRedisRevocationCache(client redis.Cmdable) *RedisRevocationCache {
	return &RedisRevocationCache{client: client}
}

// RevokeAccessToken records tokenID with ttl. The token ID is the access-token
// jti claim.
func (c *RedisRevocationCache) RevokeAccessToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	if c == nil || c.client == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "revocation cache is nil", nil)
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "access token id is required", nil)
	}
	if ttl <= 0 {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "access token revocation ttl is required", nil)
	}
	if err := c.client.Set(ctx, revokedAccessTokenKey(tokenID), "1", ttl).Err(); err != nil {
		return fmt.Errorf("session: set access token revocation: %w", err)
	}
	return nil
}

// IsAccessTokenRevoked reports whether tokenID is present in the revocation
// cache.
func (c *RedisRevocationCache) IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	if c == nil || c.client == nil {
		return false, auth.NewServiceError(auth.ErrorKindInternal, "revocation cache is nil", nil)
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return false, auth.NewServiceError(auth.ErrorKindMalformedInput, "access token id is required", nil)
	}
	count, err := c.client.Exists(ctx, revokedAccessTokenKey(tokenID)).Result()
	if err != nil {
		return false, fmt.Errorf("session: check access token revocation: %w", err)
	}
	return count > 0, nil
}

func revokedAccessTokenKey(tokenID string) string {
	return revokedAccessTokenKeyPrefix + tokenID
}
