// Command worker runs the Asynq task processor for email delivery, audit log
// shipping, PASETO key rotation, and expired-token cleanup.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
	"go.uber.org/zap"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/keys"
	"github.com/KernelFreeze/aether-auth/internal/platform/logger"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
	"github.com/KernelFreeze/aether-auth/internal/platform/queue"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
	"github.com/KernelFreeze/aether-auth/internal/workers"
)

func main() {
	if err := run(); err != nil {
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

	srv, err := queue.NewServer(ctx, cfg.Queue, sec)
	if err != nil {
		return err
	}

	keystore, err := paseto.NewKeystore(ctx, cfg.PASETO, sec, paseto.Refs{
		LocalKey:   cfg.Secrets.PASETOLocalKey,
		PublicSeed: cfg.Secrets.PASETOPublicSeed,
	})
	if err != nil {
		log.Warn("paseto keystore not initialized", zap.Error(err))
	}

	scheduler, err := queue.NewScheduler(ctx, cfg.Queue, sec)
	if err != nil {
		return err
	}

	mux := asynq.NewServeMux()
	// Task handlers are registered here as they come online:
	// mux.HandleFunc(queue.TypeEmailSend, workers.HandleEmailSend(...))
	// mux.HandleFunc(queue.TypeAuditShip, workers.HandleAuditShip(...))
	// mux.HandleFunc(queue.TypeExpiredCleanup, workers.HandleExpiredCleanup(...))
	if keystore != nil {
		mux.HandleFunc(queue.TypeKeyRotation, workers.HandleKeyRotation(keystore, log))
		if _, err := keys.RegisterRotationSchedule(scheduler, cfg.PASETO); err != nil {
			return err
		}
		if err := scheduler.Start(); err != nil {
			return err
		}
		defer scheduler.Shutdown()
	}

	go func() {
		<-ctx.Done()
		log.Info("worker_shutdown_signal")
		srv.Shutdown()
	}()

	log.Info("worker_listening")
	if err := srv.Run(mux); err != nil {
		return err
	}
	log.Info("worker_stopped")
	return nil
}
