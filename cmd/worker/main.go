// Command worker runs the Asynq task processor for email delivery, audit log
// shipping, PASETO key rotation, and expired-token cleanup.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/logger"
	"github.com/KernelFreeze/aether-auth/internal/platform/queue"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
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

	mux := asynq.NewServeMux()
	// Task handlers are registered here as they come online:
	// mux.HandleFunc(queue.TypeEmailSend, workers.HandleEmailSend(...))
	// mux.HandleFunc(queue.TypeAuditShip, workers.HandleAuditShip(...))
	// mux.HandleFunc(queue.TypeKeyRotation, workers.HandleKeyRotation(...))
	// mux.HandleFunc(queue.TypeExpiredCleanup, workers.HandleExpiredCleanup(...))

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
