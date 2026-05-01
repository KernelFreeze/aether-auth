package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type profileQueries interface {
	GetAccountByID(context.Context, pgtype.UUID) (sqlc.Account, error)
	UpdateAccountProfile(context.Context, sqlc.UpdateAccountProfileParams) (sqlc.Account, error)
}

// SQLProfileStore persists account profile settings with sqlc.
type SQLProfileStore struct {
	queries profileQueries
}

var _ ProfileStore = (*SQLProfileStore)(nil)

// NewSQLProfileStore builds a profile store backed by sqlc queries.
func NewSQLProfileStore(queries sqlc.Querier) *SQLProfileStore {
	return &SQLProfileStore{queries: queries}
}

// GetProfile returns the account profile row for accountID.
func (s *SQLProfileStore) GetProfile(ctx context.Context, accountID AccountID) (AccountProfile, error) {
	if err := s.ready(); err != nil {
		return AccountProfile{}, err
	}
	row, err := s.queries.GetAccountByID(ctx, accountIDToPG(accountID))
	if err != nil {
		return AccountProfile{}, mapProfileStoreError("get profile", err)
	}
	return profileFromSQL(row), nil
}

// UpdateProfile updates display-name and metadata settings.
func (s *SQLProfileStore) UpdateProfile(ctx context.Context, update ProfileUpdate) (AccountProfile, error) {
	if err := s.ready(); err != nil {
		return AccountProfile{}, err
	}
	if update.AccountID.IsZero() || (update.DisplayName == nil && !update.MetadataSet) {
		return AccountProfile{}, ErrInvalidProfile
	}

	row, err := s.queries.UpdateAccountProfile(ctx, sqlc.UpdateAccountProfileParams{
		ID:          accountIDToPG(update.AccountID),
		DisplayName: update.DisplayName,
		Metadata:    optionalProfileJSON(update.Metadata, update.MetadataSet),
	})
	if err != nil {
		return AccountProfile{}, mapProfileStoreError("update profile", err)
	}
	return profileFromSQL(row), nil
}

func (s *SQLProfileStore) ready() error {
	if s == nil || s.queries == nil {
		return errors.New("account: profile store is nil")
	}
	return nil
}

func profileFromSQL(row sqlc.Account) AccountProfile {
	metadata := append(json.RawMessage(nil), row.Metadata...)
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	return AccountProfile{
		ID:          accountIDFromPG(row.ID),
		Username:    row.Username,
		DisplayName: row.DisplayName,
		Metadata:    metadata,
		CreatedAt:   timestamptzToTime(row.CreatedAt),
		UpdatedAt:   timestamptzToTime(row.UpdatedAt),
	}
}

func optionalProfileJSON(raw json.RawMessage, set bool) []byte {
	if !set {
		return nil
	}
	return append([]byte(nil), raw...)
}

func mapProfileStoreError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("account: %s: %w", action, ErrProfileNotFound)
	}
	return fmt.Errorf("account: %s: %w", action, err)
}
