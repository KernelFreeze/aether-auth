// Package db owns the pgx connection pool and small helpers (transactions,
// DSN building) shared by the sqlc-generated queries.
package db

import (
	"context"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

// Open builds a pgxpool.Pool from the project's PostgresConfig, resolving the
// password through the secrets provider.
func Open(ctx context.Context, cfg config.PostgresConfig, sec secrets.Provider) (*pgxpool.Pool, error) {
	password, err := sec.Resolve(ctx, cfg.PasswordRef)
	if err != nil {
		return nil, fmt.Errorf("db: resolve password: %w", err)
	}
	dsn := buildDSN(cfg, string(password))

	pcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse pool config: %w", err)
	}
	if cfg.MaxConns > 0 {
		pcfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pcfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLife > 0 {
		pcfg.MaxConnLifetime = cfg.MaxConnLife
	}

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("db: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return pool, nil
}

func buildDSN(cfg config.PostgresConfig, password string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, password),
		Host:   fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Path:   cfg.Name,
	}
	q := u.Query()
	if cfg.SSLMode != "" {
		q.Set("sslmode", cfg.SSLMode)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
