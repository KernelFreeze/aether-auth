package totp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type attemptDB interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}

// SQLAttemptStore records MFA failures and account lockout in one transaction.
type SQLAttemptStore struct {
	db      attemptDB
	queries *sqlc.Queries
	policy  LockoutPolicy
}

var _ AttemptStore = (*SQLAttemptStore)(nil)

// NewSQLAttemptStore builds a sqlc-backed MFA attempt store.
func NewSQLAttemptStore(db attemptDB, policy LockoutPolicy) *SQLAttemptStore {
	var queries *sqlc.Queries
	if db != nil {
		queries = sqlc.New(db)
	}
	return &SQLAttemptStore{db: db, queries: queries, policy: policy}
}

// LockoutPolicyFromConfig converts runtime lockout config to MFA policy.
func LockoutPolicyFromConfig(cfg config.LockoutConfig) LockoutPolicy {
	return LockoutPolicy{
		MaxFailures:     cfg.FailuresBeforeLockout,
		BackoffSchedule: append([]time.Duration(nil), cfg.BackoffSchedule...),
		Endpoint:        defaultMFAEndpoint,
	}
}

// RecordFailure increments the factor failure row and locks the account when
// the configured threshold is reached.
func (s *SQLAttemptStore) RecordFailure(ctx context.Context, failure AttemptFailure) (AttemptResult, error) {
	if err := s.ready(); err != nil {
		return AttemptResult{}, err
	}
	if failure.AccountID.IsZero() || !failure.Factor.Valid() {
		return AttemptResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa account id and factor are required", nil)
	}
	now := normalizeAttemptTime(failure.OccurredAt)
	endpoint := attemptEndpoint(failure.Endpoint, s.policy.endpoint())
	subjectHash := attemptSubjectHash(failure.AccountID, failure.Factor)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return AttemptResult{}, fmt.Errorf("totp: begin mfa failure transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	id, err := uuid.NewV7()
	if err != nil {
		return AttemptResult{}, fmt.Errorf("totp: generate mfa attempt id: %w", err)
	}
	firstLockUntil := now.Add(s.policy.backoffFor(s.policy.maxFailures()))
	row, err := q.RecordLoginFailure(ctx, sqlc.RecordLoginFailureParams{
		ID:          uuidToPG(id),
		Endpoint:    endpoint,
		SubjectType: "account",
		SubjectHash: subjectHash,
		AccountID:   accountIDToPG(failure.AccountID),
		Ip:          optionalAttemptAddr(failure.IP),
		MaxFailures: int32(s.policy.maxFailures()),
		LockUntil:   timeToTimestamptz(firstLockUntil),
		OccurredAt:  timeToTimestamptz(now),
	})
	if err != nil {
		return AttemptResult{}, fmt.Errorf("totp: record mfa failure: %w", err)
	}

	lockedUntil := timestamptzToTime(row.LockedUntil)
	if int(row.FailedCount) >= s.policy.maxFailures() {
		lockedUntil = now.Add(s.policy.backoffFor(int(row.FailedCount)))
		if _, err := q.LockLoginAttemptUntil(ctx, sqlc.LockLoginAttemptUntilParams{
			LockedUntil: timeToTimestamptz(lockedUntil),
			Endpoint:    endpoint,
			SubjectType: "account",
			SubjectHash: subjectHash,
		}); err != nil {
			return AttemptResult{}, fmt.Errorf("totp: lock mfa attempt: %w", err)
		}
		if _, err := q.UpdateAccountLockout(ctx, sqlc.UpdateAccountLockoutParams{
			ID:          accountIDToPG(failure.AccountID),
			LockedUntil: timeToTimestamptz(lockedUntil),
		}); err != nil {
			return AttemptResult{}, fmt.Errorf("totp: update account lockout: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return AttemptResult{}, fmt.Errorf("totp: commit mfa failure transaction: %w", err)
	}
	return AttemptResult{FailedCount: int(row.FailedCount), LockedUntil: lockedUntil}, nil
}

// RecordSuccess clears failure state for the factor and account lockout.
func (s *SQLAttemptStore) RecordSuccess(ctx context.Context, success AttemptSuccess) error {
	if err := s.ready(); err != nil {
		return err
	}
	if success.AccountID.IsZero() || !success.Factor.Valid() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa account id and factor are required", nil)
	}
	now := normalizeAttemptTime(success.OccurredAt)
	endpoint := attemptEndpoint(success.Endpoint, s.policy.endpoint())
	subjectHash := attemptSubjectHash(success.AccountID, success.Factor)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("totp: begin mfa success transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	_, err = q.RecordLoginSuccess(ctx, sqlc.RecordLoginSuccessParams{
		OccurredAt:  timeToTimestamptz(now),
		Endpoint:    endpoint,
		SubjectType: "account",
		SubjectHash: subjectHash,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("totp: record mfa success: %w", err)
	}
	if _, err := q.UpdateAccountLockout(ctx, sqlc.UpdateAccountLockoutParams{
		ID:          accountIDToPG(success.AccountID),
		LockedUntil: pgtype.Timestamptz{},
	}); err != nil {
		return fmt.Errorf("totp: clear account lockout: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("totp: commit mfa success transaction: %w", err)
	}
	return nil
}

func (s *SQLAttemptStore) ready() error {
	if s == nil || s.db == nil || s.queries == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "mfa attempt store is nil", nil)
	}
	return nil
}
