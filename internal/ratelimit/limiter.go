package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	redisrate "github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
)

const defaultNamespace = "aether"

// Scope identifies the bucket that made a rate-limit decision.
type Scope string

const (
	ScopeIP       Scope = "ip"
	ScopeAccount  Scope = "account"
	ScopeUsername Scope = "username"
	ScopeEndpoint Scope = "endpoint"
)

// Limit describes a GCRA bucket.
type Limit struct {
	Rate   int
	Burst  int
	Period time.Duration
}

// Config selects the limits enforced by Checker.
type Config struct {
	Namespace             string
	PerIP                 Limit
	PerAccount            Limit
	DefaultEndpoint       Limit
	EndpointLimits        map[string]Limit
	HashIdentifyingValues bool
}

// ConfigFrom returns the rate-limit rules described by the project config.
func ConfigFrom(cfg config.RateLimitConfig) Config {
	endpoints := map[string]Limit{}
	reset := perMinute(cfg.ResetPerMinute)
	if !reset.IsZero() {
		endpoints["/password-reset"] = reset
		endpoints["/password-reset/request"] = reset
		endpoints["/auth/reset-password/request"] = reset
	}

	return Config{
		Namespace:             defaultNamespace,
		PerIP:                 perMinute(cfg.PerIPPerMinute),
		PerAccount:            perMinute(cfg.PerAccountPerMinute),
		EndpointLimits:        endpoints,
		HashIdentifyingValues: true,
	}
}

// IsZero reports whether l disables a bucket.
func (l Limit) IsZero() bool {
	return l.Rate <= 0 || l.Period <= 0
}

// Subject identifies the caller dimensions that can be rate-limited.
type Subject struct {
	IP        string
	AccountID string
	Username  string
	Endpoint  string
}

// Request describes one rate-limit decision.
type Request struct {
	Subject Subject
	Cost    int
}

// Decision reports whether the request may continue.
type Decision struct {
	Allowed    bool
	Scope      Scope
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAt    time.Time
}

// Checker checks every configured bucket for a request.
type Checker interface {
	Check(context.Context, Request) (Decision, error)
}

// BucketLimiter is the storage-level limiter used by Checker.
type BucketLimiter interface {
	Allow(ctx context.Context, key string, limit Limit, cost int) (BucketResult, error)
}

// BucketResult is the storage-level result for one bucket.
type BucketResult struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
	ResetAfter time.Duration
}

// RedisLimiter applies limits through redis_rate.
type RedisLimiter struct {
	limiter *redisrate.Limiter
}

// NewRedisLimiter builds a Redis-backed bucket limiter.
func NewRedisLimiter(client redis.UniversalClient) RedisLimiter {
	return RedisLimiter{limiter: redisrate.NewLimiter(client)}
}

// Allow checks one Redis bucket.
func (l RedisLimiter) Allow(ctx context.Context, key string, limit Limit, cost int) (BucketResult, error) {
	if cost <= 0 {
		cost = 1
	}
	res, err := l.limiter.AllowN(ctx, key, redisrate.Limit{
		Rate:   limit.Rate,
		Burst:  limit.burst(),
		Period: limit.Period,
	}, cost)
	if err != nil {
		return BucketResult{}, err
	}
	return BucketResult{
		Allowed:    res.Allowed == cost,
		Limit:      limit.Rate,
		Remaining:  res.Remaining,
		RetryAfter: res.RetryAfter,
		ResetAfter: res.ResetAfter,
	}, nil
}

// NewRedisChecker returns a Checker backed by Redis.
func NewRedisChecker(client redis.UniversalClient, cfg Config) *RuleChecker {
	return NewChecker(NewRedisLimiter(client), cfg)
}

// RuleChecker applies configured buckets to incoming requests.
type RuleChecker struct {
	limiter BucketLimiter
	config  Config
}

// NewChecker returns a rate-limit checker using limiter for storage.
func NewChecker(limiter BucketLimiter, cfg Config) *RuleChecker {
	if cfg.Namespace == "" {
		cfg.Namespace = defaultNamespace
	}
	return &RuleChecker{limiter: limiter, config: cfg}
}

// Check applies every relevant bucket and returns the first denial. On success,
// the decision reports the tightest remaining allowance.
func (c *RuleChecker) Check(ctx context.Context, req Request) (Decision, error) {
	if req.Cost <= 0 {
		req.Cost = 1
	}

	buckets := c.buckets(req.Subject)
	allowed := Decision{Allowed: true, Remaining: -1}
	for _, bucket := range buckets {
		result, err := c.limiter.Allow(ctx, bucket.key, bucket.limit, req.Cost)
		if err != nil {
			return Decision{}, fmt.Errorf("rate limit %s: %w", bucket.scope, err)
		}
		decision := decisionFromResult(bucket.scope, result)
		if !decision.Allowed {
			return decision, nil
		}
		if allowed.Remaining < 0 || decision.Remaining < allowed.Remaining {
			allowed = decision
			allowed.Allowed = true
		}
	}
	if allowed.Remaining < 0 {
		allowed.Remaining = 0
	}
	return allowed, nil
}

type bucket struct {
	scope Scope
	key   string
	limit Limit
}

func (c *RuleChecker) buckets(subject Subject) []bucket {
	endpoint := endpointKey(subject.Endpoint)
	var buckets []bucket
	if subject.IP != "" && !c.config.PerIP.IsZero() {
		buckets = append(buckets, bucket{
			scope: ScopeIP,
			key:   c.key(ScopeIP, subject.IP, endpoint),
			limit: c.config.PerIP,
		})
	}
	if subject.AccountID != "" && !c.config.PerAccount.IsZero() {
		buckets = append(buckets, bucket{
			scope: ScopeAccount,
			key:   c.key(ScopeAccount, subject.AccountID, endpoint),
			limit: c.config.PerAccount,
		})
	} else if subject.Username != "" && !c.config.PerAccount.IsZero() {
		buckets = append(buckets, bucket{
			scope: ScopeUsername,
			key:   c.key(ScopeUsername, strings.ToLower(subject.Username), endpoint),
			limit: c.config.PerAccount,
		})
	}
	if limit := c.endpointLimit(subject.Endpoint); !limit.IsZero() {
		buckets = append(buckets, bucket{
			scope: ScopeEndpoint,
			key:   c.key(ScopeEndpoint, endpoint, ""),
			limit: limit,
		})
	}
	return buckets
}

func (c *RuleChecker) endpointLimit(endpoint string) Limit {
	if endpoint == "" {
		return Limit{}
	}
	if limit, ok := c.config.EndpointLimits[endpoint]; ok {
		return limit
	}
	return c.config.DefaultEndpoint
}

func (c *RuleChecker) key(scope Scope, value, endpoint string) string {
	parts := []string{c.config.Namespace, string(scope), c.safe(value)}
	if endpoint != "" {
		parts = append(parts, endpoint)
	}
	return strings.Join(parts, ":")
}

func (c *RuleChecker) safe(value string) string {
	value = strings.TrimSpace(value)
	if c.config.HashIdentifyingValues {
		return digest(value)
	}
	value = strings.NewReplacer(":", "_", " ", "_").Replace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func endpointKey(endpoint string) string {
	if endpoint == "" {
		return "unknown"
	}
	return digest(endpoint)
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func decisionFromResult(scope Scope, result BucketResult) Decision {
	decision := Decision{
		Allowed:    result.Allowed,
		Scope:      scope,
		Limit:      result.Limit,
		Remaining:  result.Remaining,
		RetryAfter: result.RetryAfter,
	}
	if result.ResetAfter > 0 {
		decision.ResetAt = time.Now().Add(result.ResetAfter).UTC()
	}
	return decision
}

func perMinute(rate int) Limit {
	if rate <= 0 {
		return Limit{}
	}
	return Limit{Rate: rate, Burst: rate, Period: time.Minute}
}

func (l Limit) burst() int {
	if l.Burst > 0 {
		return l.Burst
	}
	return l.Rate
}
