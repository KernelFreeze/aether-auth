package totp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type recoveryCodeDB interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}

// SQLRecoveryCodeStore persists recovery-code hashes with sqlc.
type SQLRecoveryCodeStore struct {
	db      recoveryCodeDB
	queries *sqlc.Queries
}

var _ RecoveryCodeStore = (*SQLRecoveryCodeStore)(nil)

// NewSQLRecoveryCodeStore builds a recovery-code store backed by sqlc queries.
func NewSQLRecoveryCodeStore(db recoveryCodeDB) *SQLRecoveryCodeStore {
	var queries *sqlc.Queries
	if db != nil {
		queries = sqlc.New(db)
	}
	return &SQLRecoveryCodeStore{db: db, queries: queries}
}

// ReplaceRecoveryCodes deletes unused codes for the credential and stores the
// replacement hashes in one transaction.
func (s *SQLRecoveryCodeStore) ReplaceRecoveryCodes(ctx context.Context, set RecoveryCodeSet) ([]RecoveryCodeRecord, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if set.AccountID.IsZero() || set.CredentialID.IsZero() || len(set.CodeHashes) == 0 {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "recovery-code account, credential, and hashes are required", nil)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("totp: begin recovery-code replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	if _, err := q.DeleteUnusedRecoveryCodes(ctx, sqlc.DeleteUnusedRecoveryCodesParams{
		AccountID:    accountIDToPG(set.AccountID),
		CredentialID: credentialIDToPG(set.CredentialID),
	}); err != nil {
		return nil, fmt.Errorf("totp: delete unused recovery codes: %w", err)
	}

	records := make([]RecoveryCodeRecord, 0, len(set.CodeHashes))
	for _, hash := range set.CodeHashes {
		if len(hash) == 0 {
			return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "recovery-code hash is required", nil)
		}
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("totp: generate recovery-code id: %w", err)
		}
		row, err := q.CreateRecoveryCode(ctx, sqlc.CreateRecoveryCodeParams{
			ID:           uuidToPG(id),
			AccountID:    accountIDToPG(set.AccountID),
			CredentialID: credentialIDToPG(set.CredentialID),
			CodeHash:     append([]byte(nil), hash...),
		})
		if err != nil {
			return nil, fmt.Errorf("totp: create recovery code: %w", err)
		}
		records = append(records, recoveryCodeFromSQL(row))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("totp: commit recovery-code replacement: %w", err)
	}
	return records, nil
}

// ListUnusedRecoveryCodes returns active recovery-code hashes for a credential.
func (s *SQLRecoveryCodeStore) ListUnusedRecoveryCodes(ctx context.Context, accountID account.AccountID, credentialID account.CredentialID) ([]RecoveryCodeRecord, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if accountID.IsZero() || credentialID.IsZero() {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "recovery-code account and credential ids are required", nil)
	}
	rows, err := s.queries.ListUnusedRecoveryCodes(ctx, sqlc.ListUnusedRecoveryCodesParams{
		AccountID:    accountIDToPG(accountID),
		CredentialID: credentialIDToPG(credentialID),
	})
	if err != nil {
		return nil, fmt.Errorf("totp: list recovery codes: %w", err)
	}
	records := make([]RecoveryCodeRecord, 0, len(rows))
	for _, row := range rows {
		records = append(records, recoveryCodeFromSQL(row))
	}
	return records, nil
}

// ConsumeRecoveryCode marks one recovery code used. A second consume fails.
func (s *SQLRecoveryCodeStore) ConsumeRecoveryCode(ctx context.Context, consumption RecoveryCodeConsumption) (RecoveryCodeRecord, error) {
	if err := s.ready(); err != nil {
		return RecoveryCodeRecord{}, err
	}
	if consumption.ID == uuid.Nil || consumption.AccountID.IsZero() || consumption.CredentialID.IsZero() {
		return RecoveryCodeRecord{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "recovery-code id, account, and credential are required", nil)
	}
	usedAt := account.NormalizeTimestamp(consumption.UsedAt)
	if usedAt.IsZero() {
		usedAt = account.NormalizeTimestamp(time.Now())
	}
	row, err := s.queries.ConsumeRecoveryCode(ctx, sqlc.ConsumeRecoveryCodeParams{
		UsedAt:       timeToTimestamptz(usedAt),
		ID:           uuidToPG(consumption.ID),
		AccountID:    accountIDToPG(consumption.AccountID),
		CredentialID: credentialIDToPG(consumption.CredentialID),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RecoveryCodeRecord{}, auth.ErrInvalidCredentials
		}
		return RecoveryCodeRecord{}, fmt.Errorf("totp: consume recovery code: %w", err)
	}
	return recoveryCodeFromSQL(row), nil
}

func (s *SQLRecoveryCodeStore) ready() error {
	if s == nil || s.db == nil || s.queries == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "recovery-code sql store is nil", nil)
	}
	return nil
}

func recoveryCodeFromSQL(row sqlc.RecoveryCode) RecoveryCodeRecord {
	return RecoveryCodeRecord{
		ID:           uuidFromPG(row.ID),
		AccountID:    accountIDFromPG(row.AccountID),
		CredentialID: credentialIDFromPG(row.CredentialID),
		CodeHash:     append([]byte(nil), row.CodeHash...),
		UsedAt:       timestamptzToTime(row.UsedAt),
		CreatedAt:    timestamptzToTime(row.CreatedAt),
	}
}
