package password

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
)

const defaultHIBPBaseURL = "https://api.pwnedpasswords.com"

// HIBPCache stores k-anonymity range responses by SHA-1 prefix.
type HIBPCache interface {
	GetPasswordRange(context.Context, string) (string, bool, error)
	SetPasswordRange(context.Context, string, string, time.Duration) error
}

// HIBPChecker checks passwords with the Have I Been Pwned range API.
type HIBPChecker struct {
	Enabled    bool
	BaseURL    string
	CacheTTL   time.Duration
	HTTPClient *http.Client
	Cache      HIBPCache
}

var _ auth.BreachChecker = (*HIBPChecker)(nil)

// NewHIBPChecker builds a HIBP checker from runtime config.
func NewHIBPChecker(cfg config.HIBPConfig, cache HIBPCache) *HIBPChecker {
	return &HIBPChecker{
		Enabled:  cfg.Enabled,
		BaseURL:  cfg.BaseURL,
		CacheTTL: cfg.CacheTTL,
		Cache:    cache,
	}
}

// CheckPasswordBreach checks whether the password SHA-1 suffix appears in the
// range response for its first five hex characters.
func (c *HIBPChecker) CheckPasswordBreach(ctx context.Context, req auth.PasswordBreachRequest) (auth.PasswordBreachResult, error) {
	if c == nil || !c.Enabled {
		return auth.PasswordBreachResult{}, nil
	}
	prefix, suffix := passwordRangeParts(req.Password)
	body, err := c.rangeBody(ctx, prefix)
	if err != nil {
		return auth.PasswordBreachResult{}, err
	}
	count, err := breachCount(body, suffix)
	if err != nil {
		return auth.PasswordBreachResult{}, err
	}
	return auth.PasswordBreachResult{Breached: count > 0, Count: count}, nil
}

func (c *HIBPChecker) rangeBody(ctx context.Context, prefix string) (string, error) {
	if c.Cache != nil {
		body, ok, err := c.Cache.GetPasswordRange(ctx, prefix)
		if err != nil {
			return "", err
		}
		if ok {
			return body, nil
		}
	}

	baseURL := strings.TrimRight(c.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultHIBPBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/range/"+prefix, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Add-Padding", "true")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("hibp range request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hibp range request: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("hibp range body: %w", err)
	}
	body := string(data)
	if c.Cache != nil {
		if err := c.Cache.SetPasswordRange(ctx, prefix, body, c.CacheTTL); err != nil {
			return "", err
		}
	}
	return body, nil
}

func (c *HIBPChecker) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// RedisRangeCache stores HIBP range responses in Redis.
type RedisRangeCache struct {
	client redis.Cmdable
	prefix string
}

var _ HIBPCache = (*RedisRangeCache)(nil)

// NewRedisRangeCache builds a Redis-backed HIBP cache.
func NewRedisRangeCache(client redis.Cmdable) *RedisRangeCache {
	return &RedisRangeCache{client: client, prefix: "hibp:range:"}
}

// GetPasswordRange reads a cached HIBP range response.
func (c *RedisRangeCache) GetPasswordRange(ctx context.Context, prefix string) (string, bool, error) {
	if c == nil || c.client == nil {
		return "", false, nil
	}
	value, err := c.client.Get(ctx, c.prefix+prefix).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetPasswordRange stores a HIBP range response.
func (c *RedisRangeCache) SetPasswordRange(ctx context.Context, prefix, body string, ttl time.Duration) error {
	if c == nil || c.client == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return c.client.Set(ctx, c.prefix+prefix, body, ttl).Err()
}

func passwordRangeParts(password string) (string, string) {
	sum := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))
	return encoded[:5], encoded[5:]
}

func breachCount(body, suffix string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		gotSuffix, countText, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(gotSuffix, suffix) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(countText))
		if err != nil {
			return 0, fmt.Errorf("parse hibp count: %w", err)
		}
		return count, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}
