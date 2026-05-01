//go:build integration

package testutil

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

// PostgresDB is a migrated Postgres database for integration tests.
type PostgresDB struct {
	Pool    *pgxpool.Pool
	Queries *sqlc.Queries
	DSN     string
}

// NewPostgresDB starts Postgres, applies project migrations, and returns a
// pgx pool with sqlc queries bound to it.
func NewPostgresDB(t testing.TB) *PostgresDB {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	ctr, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("aether_auth_test"),
		postgres.WithUsername("aether"),
		postgres.WithPassword("aether"),
		postgres.BasicWaitStrategies(),
	)
	if ctr != nil {
		testcontainers.CleanupContainer(t, ctr)
	}
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("build postgres connection string: %v", err)
	}
	applyMigrations(t, dsn)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}

	return &PostgresDB{
		Pool:    pool,
		Queries: sqlc.New(pool),
		DSN:     dsn,
	}
}

func applyMigrations(t testing.TB, dsn string) {
	t.Helper()

	m, err := migrate.New(migrationsURL(t), dsn)
	if err != nil {
		t.Fatalf("open migrations: %v", err)
	}
	defer func() {
		if sourceErr, dbErr := m.Close(); sourceErr != nil || dbErr != nil {
			t.Fatalf("close migrations: source=%v database=%v", sourceErr, dbErr)
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("apply migrations: %v", err)
	}
}

func migrationsURL(t testing.TB) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test helper source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	return fmt.Sprintf("file://%s", filepath.ToSlash(filepath.Join(root, "migrations")))
}
