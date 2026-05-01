// Command api boots the auth service's HTTP listener.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/KernelFreeze/aether-auth/internal/account"
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

func shutdownTimeout(cfg *config.Config) time.Duration {
	if cfg.Server.ShutdownTimeout > 0 {
		return cfg.Server.ShutdownTimeout
	}
	return 10 * time.Second
}
