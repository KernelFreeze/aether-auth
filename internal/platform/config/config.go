// Package config defines the project's environment-driven configuration
// surface. All values are loaded by Load using sethvargo/go-envconfig; secrets
// (pepper, PASETO keys, AES key, OIDC client secrets, DB/Redis/SMTP passwords)
// are referenced by URI strings and resolved through internal/platform/secrets.
package config

import (
	"context"
	"time"

	"github.com/sethvargo/go-envconfig"
)

// Config is the top-level configuration tree. Each subsystem owns its own
// nested struct so the boundary between concerns is visible at the type level.
type Config struct {
	Server     ServerConfig
	Postgres   PostgresConfig
	Redis      RedisConfig
	Mailer     MailerConfig
	Queue      QueueConfig
	Issuer     IssuerConfig
	Secrets    SecretsConfig
	Argon2     Argon2Config
	Session    SessionConfig
	PASETO     PASETOConfig
	OAuth      OAuthServerConfig
	OIDC       OIDCConfig
	RateLimits RateLimitConfig
	Lockout    LockoutConfig
	HIBP       HIBPConfig
	CSRF       CSRFConfig
	CORS       CORSConfig
	Audit      AuditConfig
	Logging    LoggingConfig
	Org        OrgConfig
}

// Load reads the configuration from process environment variables using the
// envconfig tags on each nested struct.
func Load(ctx context.Context) (*Config, error) {
	var c Config
	if err := envconfig.Process(ctx, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	Port            string        `env:"SERVER_PORT, default=8080"`
	Env             string        `env:"SERVER_ENV, default=development"`
	ReadTimeout     time.Duration `env:"SERVER_READ_TIMEOUT, default=5s"`
	WriteTimeout    time.Duration `env:"SERVER_WRITE_TIMEOUT, default=10s"`
	ShutdownTimeout time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT, default=10s"`
}

// PostgresConfig configures the pgx connection pool.
type PostgresConfig struct {
	Host        string        `env:"DB_HOST, default=localhost"`
	Port        string        `env:"DB_PORT, default=5432"`
	User        string        `env:"DB_USER, default=postgres"`
	PasswordRef string        `env:"DB_PASSWORD_REF, default=env://DB_PASSWORD"`
	Name        string        `env:"DB_NAME, default=aether_auth"`
	SSLMode     string        `env:"DB_SSL_MODE, default=disable"`
	MaxConns    int32         `env:"DB_MAX_CONNS, default=20"`
	MinConns    int32         `env:"DB_MIN_CONNS, default=2"`
	MaxConnLife time.Duration `env:"DB_MAX_CONN_LIFETIME, default=1h"`
}

// RedisConfig configures the redis client used for rate limiting, the token
// revocation set, and Asynq.
type RedisConfig struct {
	Addr        string `env:"REDIS_ADDR, default=localhost:6379"`
	PasswordRef string `env:"REDIS_PASSWORD_REF, default=env://REDIS_PASSWORD"`
	DB          int    `env:"REDIS_DB, default=0"`
}

// MailerConfig configures the SMTP transport for transactional email.
type MailerConfig struct {
	Host        string `env:"SMTP_HOST, default=localhost"`
	Port        int    `env:"SMTP_PORT, default=1025"`
	Username    string `env:"SMTP_USERNAME"`
	PasswordRef string `env:"SMTP_PASSWORD_REF, default=env://SMTP_PASSWORD"`
	From        string `env:"SMTP_FROM, default=noreply@example.com"`
	StartTLS    bool   `env:"SMTP_STARTTLS, default=false"`
}

// QueueConfig configures the Asynq broker shared between the API and worker.
type QueueConfig struct {
	RedisAddr   string `env:"QUEUE_REDIS_ADDR, default=localhost:6379"`
	PasswordRef string `env:"QUEUE_REDIS_PASSWORD_REF, default=env://QUEUE_REDIS_PASSWORD"`
	DB          int    `env:"QUEUE_REDIS_DB, default=1"`
	Concurrency int    `env:"QUEUE_CONCURRENCY, default=10"`
}

// IssuerConfig holds the auth service's identity (the iss claim) and the
// public base URL used to build redirect URIs and email links.
type IssuerConfig struct {
	URL       string   `env:"ISSUER_URL, default=https://auth.example.com"`
	BaseURL   string   `env:"PUBLIC_BASE_URL, default=https://auth.example.com"`
	Audiences []string `env:"ISSUER_AUDIENCES, default=https://api.example.com"`
}

// SecretsConfig holds URI references to the project's cryptographic secrets.
// Each value is resolved through internal/platform/secrets.Provider; the env://
// scheme is the only one wired up at scaffold time.
type SecretsConfig struct {
	Pepper           string `env:"SECRET_PEPPER_REF, default=env://AUTH_PEPPER"`
	AESKey           string `env:"SECRET_AES_KEY_REF, default=env://AUTH_AES_KEY"`
	PASETOLocalKey   string `env:"SECRET_PASETO_LOCAL_REF, default=env://AUTH_PASETO_LOCAL_KEY"`
	PASETOPublicSeed string `env:"SECRET_PASETO_SEED_REF, default=env://AUTH_PASETO_SEED"`
	CSRFSecret       string `env:"SECRET_CSRF_REF, default=env://AUTH_CSRF_SECRET"`
}

// Argon2Config matches the OWASP-recommended Argon2id parameter ranges.
type Argon2Config struct {
	Memory      uint32 `env:"ARGON2_MEMORY_KIB, default=47104"`
	Iterations  uint32 `env:"ARGON2_ITERATIONS, default=1"`
	Parallelism uint8  `env:"ARGON2_PARALLELISM, default=1"`
	SaltLength  uint32 `env:"ARGON2_SALT_LENGTH, default=16"`
	KeyLength   uint32 `env:"ARGON2_KEY_LENGTH, default=32"`
}

// SessionConfig configures session lifetimes.
type SessionConfig struct {
	AccessTTL          time.Duration `env:"SESSION_ACCESS_TTL, default=15m"`
	RefreshSliding     time.Duration `env:"SESSION_REFRESH_SLIDING, default=720h"`
	RefreshAbsolute    time.Duration `env:"SESSION_REFRESH_ABSOLUTE, default=2160h"`
	PartialSessionTTL  time.Duration `env:"SESSION_PARTIAL_TTL, default=2m"`
	RevocationCacheTTL time.Duration `env:"SESSION_REVOCATION_CACHE_TTL, default=15m"`
}

// PASETOConfig configures PASETO key rotation and the kid scheme.
type PASETOConfig struct {
	RotationInterval time.Duration `env:"PASETO_ROTATION_INTERVAL, default=2160h"`
	OverlapWindow    time.Duration `env:"PASETO_OVERLAP_WINDOW, default=336h"`
}

// OAuthServerConfig configures the OAuth2 authorization server (Fosite).
type OAuthServerConfig struct {
	CodeTTL             time.Duration `env:"OAUTH_CODE_TTL, default=60s"`
	AccessTTL           time.Duration `env:"OAUTH_ACCESS_TTL, default=15m"`
	RefreshTTL          time.Duration `env:"OAUTH_REFRESH_TTL, default=720h"`
	RotateRefreshTokens bool          `env:"OAUTH_ROTATE_REFRESH, default=true"`
	DefaultScopes       []string      `env:"OAUTH_DEFAULT_SCOPES, default=openid,profile"`
	RequirePKCE         bool          `env:"OAUTH_REQUIRE_PKCE, default=true"`
}

// OIDCConfig configures upstream identity providers (google, github, apple,
// microsoft, discord, ...). At scaffold time only the comma-separated list of
// enabled provider slugs is captured here; per-provider client_id /
// client_secret_ref / discovery URL are loaded by internal/auth/oidc when it
// fills in, since each value also needs to flow through secrets.Provider.
type OIDCConfig struct {
	EnabledProviders []string `env:"OIDC_PROVIDERS"`
}

// RateLimitConfig configures per-IP, per-account, and per-endpoint buckets.
type RateLimitConfig struct {
	PerIPPerMinute      int `env:"RATELIMIT_IP_PER_MIN, default=100"`
	PerAccountPerMinute int `env:"RATELIMIT_ACCOUNT_PER_MIN, default=10"`
	ResetPerMinute      int `env:"RATELIMIT_RESET_PER_MIN, default=5"`
}

// LockoutConfig configures progressive lockout after consecutive failures.
type LockoutConfig struct {
	FailuresBeforeLockout int             `env:"LOCKOUT_FAILURES, default=5"`
	BackoffSchedule       []time.Duration `env:"LOCKOUT_BACKOFF, default=1m,5m,15m,1h"`
	CaptchaAfterFailures  int             `env:"LOCKOUT_CAPTCHA_AFTER, default=3"`
}

// HIBPConfig controls the Have I Been Pwned breach-corpus check.
type HIBPConfig struct {
	Enabled  bool          `env:"HIBP_ENABLED, default=true"`
	BaseURL  string        `env:"HIBP_BASE_URL, default=https://api.pwnedpasswords.com"`
	CacheTTL time.Duration `env:"HIBP_CACHE_TTL, default=24h"`
}

// CSRFConfig configures the synchronizer-token cookie/header pair.
type CSRFConfig struct {
	CookieName string `env:"CSRF_COOKIE, default=XSRF-TOKEN"`
	HeaderName string `env:"CSRF_HEADER, default=X-XSRF-TOKEN"`
}

// CORSConfig configures the CORS middleware applied to API routes.
type CORSConfig struct {
	AllowedOrigins []string `env:"CORS_ORIGINS, default=*"`
	AllowedMethods []string `env:"CORS_METHODS, default=GET,POST,PUT,PATCH,DELETE,OPTIONS"`
	AllowedHeaders []string `env:"CORS_HEADERS, default=Authorization,Content-Type,X-XSRF-TOKEN"`
}

// AuditConfig selects the sink for the append-only audit log.
type AuditConfig struct {
	Sink string `env:"AUDIT_SINK, default=db"`
}

// LoggingConfig configures the zap logger.
type LoggingConfig struct {
	Development bool   `env:"LOG_DEVELOPMENT, default=false"`
	Level       string `env:"LOG_LEVEL, default=info"`
}

// OrgConfig holds organization-wide defaults.
type OrgConfig struct {
	DefaultRole   string        `env:"ORG_DEFAULT_ROLE, default=member"`
	InvitationTTL time.Duration `env:"ORG_INVITATION_TTL, default=168h"`
}
