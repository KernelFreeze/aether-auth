// Command migrate is a thin wrapper around golang-migrate. It loads the
// project's PostgresConfig, resolves the password through the secrets
// provider, and applies up/down migrations from /migrations against the
// configured database.
//
// Usage:
//
//	migrate up                # apply all pending migrations
//	migrate down              # roll back the most recent migration
//	migrate down 3            # roll back the last 3 migrations
//	migrate force <version>   # override the dirty flag at the given version
//	migrate version           # print the current schema version
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

const migrationsPath = "file://migrations"

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: migrate {up|down [N]|force <version>|version}")
	}
	ctx := context.Background()
	cfg, err := config.Load(ctx)
	if err != nil {
		return err
	}
	sec := secrets.NewMux()
	password, err := sec.Resolve(ctx, cfg.Postgres.PasswordRef)
	if err != nil {
		return fmt.Errorf("migrate: resolve password: %w", err)
	}
	dsn := buildDSN(cfg.Postgres, string(password))

	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		return fmt.Errorf("migrate: open: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	switch args[0] {
	case "up":
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return err
		}
	case "down":
		n := 1
		if len(args) > 1 {
			parsed, perr := strconv.Atoi(args[1])
			if perr != nil {
				return fmt.Errorf("migrate down: invalid count %q", args[1])
			}
			n = parsed
		}
		if err := m.Steps(-n); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return err
		}
	case "force":
		if len(args) < 2 {
			return errors.New("migrate force: missing version")
		}
		v, perr := strconv.Atoi(args[1])
		if perr != nil {
			return fmt.Errorf("migrate force: invalid version %q", args[1])
		}
		if err := m.Force(v); err != nil {
			return err
		}
	case "version":
		v, dirty, err := m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			return err
		}
		fmt.Printf("version=%d dirty=%v\n", v, dirty)
	default:
		return fmt.Errorf("migrate: unknown command %q", args[0])
	}
	return nil
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
