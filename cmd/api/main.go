// Command api boots the auth service's HTTP listener.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/password"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/db"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
	"github.com/KernelFreeze/aether-auth/internal/platform/logger"
	"github.com/KernelFreeze/aether-auth/internal/platform/mailer"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/platform/queue"
	platformredis "github.com/KernelFreeze/aether-auth/internal/platform/redis"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
	"github.com/KernelFreeze/aether-auth/internal/ratelimit"
	"github.com/KernelFreeze/aether-auth/internal/server"
)

func main() {
	if err := run(); err != nil {
		// stderr fallback when zap may not be available yet
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}

	log, err := logger.New(cfg.Logging.Development)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	sec := secrets.NewMux()

	pool, err := db.Open(ctx, cfg.Postgres, sec)
	if err != nil {
		return err
	}
	defer pool.Close()

	rdb, err := platformredis.Open(ctx, cfg.Redis, sec)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	asynqClient, err := queue.NewClient(ctx, cfg.Queue, sec)
	if err != nil {
		return err
	}
	defer func() { _ = asynqClient.Close() }()

	mail, err := mailer.New(ctx, cfg.Mailer, sec)
	if err != nil {
		return err
	}
	defer func() { _ = mail.Close() }()

	keystore, err := paseto.NewKeystore(ctx, cfg.PASETO, sec, paseto.Refs{
		LocalKey:   cfg.Secrets.PASETOLocalKey,
		PublicSeed: cfg.Secrets.PASETOPublicSeed,
	})
	if err != nil {
		log.Warn("paseto keystore not initialized", zap.Error(err))
	}

	queries := sqlc.New(pool)
	rateLimiter := ratelimit.NewRedisChecker(rdb, ratelimit.ConfigFrom(cfg.RateLimits))
	passwordService, err := newPasswordService(ctx, cfg, sec, pool, queries, rdb)
	if err != nil {
		return err
	}
	orchestrator, err := auth.NewOrchestratorWithDeps(auth.OrchestratorDeps{
		Accounts:          auth.NewSQLAccountRepository(queries),
		RateLimiter:       authRateLimiter{checker: rateLimiter},
		Audit:             auth.NewSQLAuditWriter(queries),
		DummyPasswordWork: passwordService,
	}, passwordService)
	if err != nil {
		return err
	}
	router := httpapi.NewRouter(httpapi.Deps{
		Config:     cfg,
		Logger:     log,
		PASETOKeys: keystore,
		Modules: httpapi.FeatureModules{
			Account: account.New(account.Deps{
				Profiles: account.NewProfileService(account.ProfileDeps{
					Store: account.NewSQLProfileStore(queries),
				}),
				Credentials: account.NewCredentialService(account.CredentialDeps{
					Store: account.NewSQLCredentialStore(queries),
				}),
			}),
			Auth: auth.New(auth.Deps{
				Registration: account.NewRegistrationService(account.RegistrationDeps{
					Store: account.NewSQLRegistrationStore(pool),
					Audit: account.NewSQLRegistrationAuditWriter(queries),
				}),
				Login: orchestrator,
			}),
		},
		Middlewares: httpapi.Middlewares{
			RateLimit: ratelimit.NewMiddleware(rateLimiter),
		},
	})

	srv := server.NewServer(router, server.Options{
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	})

	errCh := make(chan error, 1)
	go func() {
		log.Info("api_listening", zap.String("port", cfg.Server.Port))
		if err := srv.Start(cfg.Server.Port); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		log.Info("api_shutdown_signal")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout(cfg))
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("api_shutdown_failed", zap.Error(err))
		return err
	}
	log.Info("api_stopped")
	return nil
}

func newPasswordService(ctx context.Context, cfg *config.Config, sec secrets.Provider, pool interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}, queries sqlc.Querier, rdb interface {
	redis.Cmdable
}) (*password.Service, error) {
	pepper, err := sec.Resolve(ctx, cfg.Secrets.Pepper)
	if err != nil {
		return nil, err
	}
	box, err := password.NewAESGCMBox(ctx, sec, cfg.Secrets.AESKey, rand.Reader)
	if err != nil {
		return nil, err
	}
	hasher := password.NewArgon2idHasher(cfg.Argon2, pepper, rand.Reader)
	dummyHash, err := hasher.HashPassword(ctx, auth.PasswordHashRequest{Password: "aether-auth dummy password"})
	if err != nil {
		return nil, err
	}

	return password.New(password.Deps{
		Credentials: auth.NewSQLCredentialRepository(queries, auth.UUIDGenerator{}, auth.CredentialPayloadConfig{
			Algorithm: "aes-256-gcm",
			KeyRef:    cfg.Secrets.AESKey,
			Version:   1,
		}),
		Hasher:            hasher,
		Policy:            password.NISTPolicy{},
		Breaches:          password.NewHIBPChecker(cfg.HIBP, password.NewRedisRangeCache(rdb)),
		Box:               box,
		Attempts:          password.NewSQLAttemptStore(pool, password.LockoutPolicyFromConfig(cfg.Lockout)),
		PartialSessionTTL: cfg.Session.PartialSessionTTL,
		DummyHash:         dummyHash,
	}), nil
}

func shutdownTimeout(cfg *config.Config) time.Duration {
	if cfg.Server.ShutdownTimeout > 0 {
		return cfg.Server.ShutdownTimeout
	}
	return 10 * time.Second
}

type authRateLimiter struct {
	checker ratelimit.Checker
}

func (l authRateLimiter) CheckRateLimit(ctx context.Context, req auth.RateLimitRequest) (auth.RateLimitResult, error) {
	if l.checker == nil {
		return auth.RateLimitResult{}, auth.NewServiceError(auth.ErrorKindInternal, "rate limiter is nil", nil)
	}
	var accountID string
	if !req.Subject.AccountID.IsZero() {
		accountID = req.Subject.AccountID.String()
	}
	decision, err := l.checker.Check(ctx, ratelimit.Request{
		Subject: ratelimit.Subject{
			IP:        req.Subject.IP,
			AccountID: accountID,
			Username:  req.Subject.Username,
			Endpoint:  req.Subject.Endpoint,
		},
		Cost: req.Cost,
	})
	if err != nil {
		return auth.RateLimitResult{}, err
	}
	return auth.RateLimitResult{
		Allowed:    decision.Allowed,
		Limit:      decision.Limit,
		Remaining:  decision.Remaining,
		RetryAfter: decision.RetryAfter,
		ResetAt:    decision.ResetAt,
	}, nil
}
