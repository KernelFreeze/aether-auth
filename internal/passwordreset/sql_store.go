package passwordreset

import (
	"context"
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
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type resetQueries interface {
	CreatePasswordResetToken(context.Context, sqlc.CreatePasswordResetTokenParams) (sqlc.PasswordResetToken, error)
	GetPasswordResetTargetByEmail(context.Context, string) (sqlc.GetPasswordResetTargetByEmailRow, error)
	GetPasswordResetTargetByUsername(context.Context, string) (sqlc.GetPasswordResetTargetByUsernameRow, error)
}

// SQLStore persists password reset tokens with sqlc.
type SQLStore struct {
	queries resetQueries
}

var _ Store = (*SQLStore)(nil)

// NewSQLStore builds a password reset store backed by sqlc queries.
func NewSQLStore(queries sqlc.Querier) *SQLStore {
	return &SQLStore{queries: queries}
}

// LookupResetTarget returns the account and primary email for a reset request.
func (s *SQLStore) LookupResetTarget(ctx context.Context, lookup ResetLookup) (ResetTarget, error) {
	if s == nil || s.queries == nil {
		return ResetTarget{}, auth.NewServiceError(auth.ErrorKindInternal, "password reset queries are nil", nil)
	}

	switch {
	case strings.TrimSpace(lookup.Username) != "":
		row, err := s.queries.GetPasswordResetTargetByUsername(ctx, normalizeIdentifier(lookup.Username))
		if err != nil {
			return ResetTarget{}, mapResetStoreError("lookup reset target by username", err)
		}
		return resetTargetFromUsernameRow(row), nil
	case strings.TrimSpace(lookup.Email) != "":
		row, err := s.queries.GetPasswordResetTargetByEmail(ctx, normalizeIdentifier(lookup.Email))
		if err != nil {
			return ResetTarget{}, mapResetStoreError("lookup reset target by email", err)
		}
		return resetTargetFromEmailRow(row), nil
	default:
		return ResetTarget{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "reset lookup key is required", nil)
	}
}

// CreateResetToken stores a hashed reset token.
func (s *SQLStore) CreateResetToken(ctx context.Context, draft ResetTokenDraft) error {
	if s == nil || s.queries == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset queries are nil", nil)
	}
	if draft.ID == uuid.Nil || draft.AccountID.IsZero() || len(draft.TokenHash) == 0 || draft.ExpiresAt.IsZero() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "password reset token draft is incomplete", nil)
	}

	ip, err := optionalAddr(draft.RequestedByIP)
	if err != nil {
		return err
	}
	_, err = s.queries.CreatePasswordResetToken(ctx, sqlc.CreatePasswordResetTokenParams{
		ID:            uuidToPG(draft.ID),
		AccountID:     accountIDToPG(draft.AccountID),
		TokenHash:     append([]byte(nil), draft.TokenHash...),
		RequestedByIp: ip,
		UserAgent:     draft.UserAgent,
		ExpiresAt:     timeToPG(draft.ExpiresAt),
	})
	return mapResetStoreError("create reset token", err)
}

func resetTargetFromUsernameRow(row sqlc.GetPasswordResetTargetByUsernameRow) ResetTarget {
	return ResetTarget{
		AccountID: accountIDFromPG(row.ID),
		Username:  row.Username,
		Email:     row.EmailAddress,
	}
}

func resetTargetFromEmailRow(row sqlc.GetPasswordResetTargetByEmailRow) ResetTarget {
	return ResetTarget{
		AccountID: accountIDFromPG(row.ID),
		Username:  row.Username,
		Email:     row.EmailAddress,
	}
}

func mapResetStoreError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrInvalidCredentials
	}
	return fmt.Errorf("passwordreset: %s: %w", action, err)
}

func optionalAddr(value string) (*netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "password reset ip is malformed", err)
	}
	return &addr, nil
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: id != uuid.Nil}
}

func accountIDToPG(id account.AccountID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func accountIDFromPG(id pgtype.UUID) account.AccountID {
	if !id.Valid {
		return account.AccountID(uuid.Nil)
	}
	return account.AccountID(uuid.UUID(id.Bytes))
}

func timeToPG(t time.Time) pgtype.Timestamptz {
	t = account.NormalizeTimestamp(t)
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}
