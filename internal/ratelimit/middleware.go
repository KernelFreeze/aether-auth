package ratelimit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

const (
	rateLimitProblemType = "https://aether-auth.local/problems/rate-limited"
	rateLimitCode        = "rate_limited"
)

// SubjectFunc returns the caller dimensions available before a handler runs.
type SubjectFunc func(*gin.Context) Subject

// MiddlewareOption customizes one route's rate-limit middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	cost     int
	endpoint string
	subject  SubjectFunc
	failOpen bool
}

// NewMiddleware returns a route-middleware factory. Defaults are applied to
// every route and per-route options may add endpoint or subject extraction.
func NewMiddleware(checker Checker, defaults ...MiddlewareOption) func(...MiddlewareOption) gin.HandlerFunc {
	return func(options ...MiddlewareOption) gin.HandlerFunc {
		cfg := middlewareConfig{cost: 1}
		for _, apply := range defaults {
			apply(&cfg)
		}
		for _, apply := range options {
			apply(&cfg)
		}
		return middleware(checker, cfg)
	}
}

// WithEndpoint overrides the bucket endpoint. By default the Gin route pattern
// is used, falling back to the request path.
func WithEndpoint(endpoint string) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.endpoint = endpoint
	}
}

// WithCost charges more than one token for an expensive request.
func WithCost(cost int) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.cost = cost
	}
}

// WithSubject adds account or username dimensions before auth verification.
func WithSubject(subject SubjectFunc) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.subject = subject
	}
}

// WithFailOpen allows requests through when the backing limiter is unavailable.
func WithFailOpen() MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.failOpen = true
	}
}

func middleware(checker Checker, cfg middlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := Subject{
			IP:       c.ClientIP(),
			Endpoint: routeEndpoint(c, cfg.endpoint),
		}
		if cfg.subject != nil {
			extra := cfg.subject(c)
			if extra.IP != "" {
				subject.IP = extra.IP
			}
			if extra.AccountID != "" {
				subject.AccountID = extra.AccountID
			}
			if extra.Username != "" {
				subject.Username = extra.Username
			}
			if extra.Endpoint != "" {
				subject.Endpoint = extra.Endpoint
			}
		}

		decision, err := checker.Check(c.Request.Context(), Request{
			Subject: subject,
			Cost:    cfg.cost,
		})
		if err != nil {
			if cfg.failOpen {
				c.Next()
				return
			}
			writeUnavailable(c)
			return
		}
		setHeaders(c, decision)
		if !decision.Allowed {
			writeLimited(c, decision)
			return
		}
		c.Next()
	}
}

func routeEndpoint(c *gin.Context, override string) string {
	if override != "" {
		return override
	}
	if fullPath := c.FullPath(); fullPath != "" {
		return fullPath
	}
	return c.Request.URL.Path
}

func setHeaders(c *gin.Context, d Decision) {
	if d.Limit > 0 {
		c.Header("X-RateLimit-Limit", strconv.Itoa(d.Limit))
	}
	if d.Remaining >= 0 {
		c.Header("X-RateLimit-Remaining", strconv.Itoa(d.Remaining))
	}
	if !d.ResetAt.IsZero() {
		c.Header("X-RateLimit-Reset", strconv.FormatInt(d.ResetAt.Unix(), 10))
	}
}

func writeLimited(c *gin.Context, d Decision) {
	if d.RetryAfter > 0 {
		c.Header("Retry-After", strconv.Itoa(int(d.RetryAfter.Round(time.Second).Seconds())))
	}
	httpx.WriteProblem(c, httpx.Problem{
		Type:   rateLimitProblemType,
		Title:  "Too many requests",
		Status: http.StatusTooManyRequests,
		Code:   rateLimitCode,
		Detail: "Too many requests. Try again later.",
	})
}

func writeUnavailable(c *gin.Context) {
	httpx.WriteProblem(c, httpx.Problem{
		Type:   "https://aether-auth.local/problems/rate-limit-unavailable",
		Title:  "Rate limit unavailable",
		Status: http.StatusServiceUnavailable,
		Code:   "rate_limit_unavailable",
		Detail: "Rate limiting is unavailable.",
	})
}
