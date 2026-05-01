package password

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type attemptDB interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}

// SQLAttemptStore records password failures and account lockout in one
// transaction.
type SQLAttemptStore struct {
	db      attemptDB
	queries *sqlc.Queries
	policy  LockoutPolicy
}

var _ AttemptStore = (*SQLAttemptStore)(nil)

// NewSQLAttemptStore builds a sqlc-backed login-attempt store.
func NewSQLAttemptStore(db attemptDB, policy LockoutPolicy) *SQLAttemptStore {
	var queries *sqlc.Queries
	if db != nil {
		queries = sqlc.New(db)
	}
	return &SQLAttemptStore{db: db, queries: queries, policy: policy}
}

// LockoutPolicyFromConfig converts runtime lockout config to password policy.
func LockoutPolicyFromConfig(cfg config.LockoutConfig) LockoutPolicy {
	return LockoutPolicy{
		MaxFailures:     cfg.FailuresBeforeLockout,
		BackoffSchedule: append([]time.Duration(nil), cfg.BackoffSchedule...),
		Endpoint:        defaultLoginEndpoint,
	}
}

// RecordFailure increments the account failure row and locks the account when
// the configured threshold is reached.
func (s *SQLAttemptStore) RecordFailure(ctx context.Context, failure AttemptFailure) (AttemptResult, error) {
	if err := s.ready(); err != nil {
		return AttemptResult{}, err
	}
	if failure.AccountID.IsZero() {
		return AttemptResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	now := normalizeAttemptTime(failure.OccurredAt)
	endpoint := attemptEndpoint(failure.Endpoint, s.policy.endpoint())

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return AttemptResult{}, fmt.Errorf("password: begin login failure transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	id, err := uuid.NewV7()
	if err != nil {
		return AttemptResult{}, fmt.Errorf("password: generate login attempt id: %w", err)
	}
	firstLockUntil := now.Add(s.policy.backoffFor(s.policy.maxFailures()))
	row, err := q.RecordLoginFailure(ctx, sqlc.RecordLoginFailureParams{
		ID:                 uuidToPG(id),
		Endpoint:           endpoint,
		SubjectType:        "account",
		SubjectHash:        accountSubjectHash(failure.AccountID),
		AccountID:          accountIDToPG(failure.AccountID),
		UsernameNormalized: optionalAttemptString(normalizeUsername(failure.Username)),
		Ip:                 optionalAttemptAddr(failure.IP),
		MaxFailures:        int32(s.policy.maxFailures()),
		LockUntil:          timeToTimestamptz(firstLockUntil),
		OccurredAt:         timeToTimestamptz(now),
	})
	if err != nil {
		return AttemptResult{}, fmt.Errorf("password: record login failure: %w", err)
	}

	lockedUntil := timestamptzToTime(row.LockedUntil)
	if int(row.FailedCount) >= s.policy.maxFailures() {
		lockedUntil = now.Add(s.policy.backoffFor(int(row.FailedCount)))
		if _, err := q.LockLoginAttemptUntil(ctx, sqlc.LockLoginAttemptUntilParams{
			LockedUntil: timeToTimestamptz(lockedUntil),
			Endpoint:    endpoint,
			SubjectType: "account",
			SubjectHash: accountSubjectHash(failure.AccountID),
		}); err != nil {
			return AttemptResult{}, fmt.Errorf("password: lock login attempt: %w", err)
		}
		if _, err := q.UpdateAccountLockout(ctx, sqlc.UpdateAccountLockoutParams{
			ID:          accountIDToPG(failure.AccountID),
			LockedUntil: timeToTimestamptz(lockedUntil),
		}); err != nil {
			return AttemptResult{}, fmt.Errorf("password: update account lockout: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return AttemptResult{}, fmt.Errorf("password: commit login failure transaction: %w", err)
	}
	return AttemptResult{FailedCount: int(row.FailedCount), LockedUntil: lockedUntil}, nil
}

// RecordSuccess clears login failure state and account lockout.
func (s *SQLAttemptStore) RecordSuccess(ctx context.Context, success AttemptSuccess) error {
	if err := s.ready(); err != nil {
		return err
	}
	if success.AccountID.IsZero() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	now := normalizeAttemptTime(success.OccurredAt)
	endpoint := attemptEndpoint(success.Endpoint, s.policy.endpoint())

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("password: begin login success transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	_, err = q.RecordLoginSuccess(ctx, sqlc.RecordLoginSuccessParams{
		OccurredAt:  timeToTimestamptz(now),
		Endpoint:    endpoint,
		SubjectType: "account",
		SubjectHash: accountSubjectHash(success.AccountID),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("password: record login success: %w", err)
	}
	if _, err := q.UpdateAccountLockout(ctx, sqlc.UpdateAccountLockoutParams{
		ID:          accountIDToPG(success.AccountID),
		LockedUntil: pgtype.Timestamptz{},
	}); err != nil {
		return fmt.Errorf("password: clear account lockout: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("password: commit login success transaction: %w", err)
	}
	return nil
}

func (s *SQLAttemptStore) ready() error {
	if s == nil || s.db == nil || s.queries == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "login attempt store is nil", nil)
	}
	return nil
}

func normalizeAttemptTime(t time.Time) time.Time {
	if t.IsZero() {
		t = time.Now()
	}
	return account.NormalizeTimestamp(t)
}

func attemptEndpoint(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func accountSubjectHash(id account.AccountID) string {
	sum := sha256.Sum256([]byte(id.String()))
	return hex.EncodeToString(sum[:])
}

func optionalAttemptString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func optionalAttemptAddr(ip netip.Addr) *netip.Addr {
	if !ip.IsValid() {
		return nil
	}
	return &ip
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: id != uuid.Nil}
}

func accountIDToPG(id account.AccountID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func timeToTimestamptz(t time.Time) pgtype.Timestamptz {
	t = account.NormalizeTimestamp(t)
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}

func timestamptzToTime(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return account.NormalizeTimestamp(t.Time)
}
