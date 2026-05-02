package session

import (
	"context"
	"encoding/json"
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

type transactionDB interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}

// SQLStore persists sessions and refresh-token hashes with sqlc.
type SQLStore struct {
	db      transactionDB
	queries *sqlc.Queries
}

var _ Store = (*SQLStore)(nil)

// NewSQLStore builds a session store backed by sqlc queries.
func NewSQLStore(db transactionDB, queries *sqlc.Queries) *SQLStore {
	if queries == nil && db != nil {
		queries = sqlc.New(db)
	}
	return &SQLStore{db: db, queries: queries}
}

// CreateFullSession writes the full session, verified factors, and refresh
// token hash in one database transaction.
func (s *SQLStore) CreateFullSession(ctx context.Context, record FullSessionRecord) error {
	if err := s.ready(); err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("session: begin full session transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.queries.WithTx(tx)
	if err := createSessionRecord(ctx, q, record.Session, record.UserAgent); err != nil {
		return err
	}
	for _, factor := range record.Factors {
		if err := createFactorRecord(ctx, q, factor); err != nil {
			return err
		}
	}
	if err := createRefreshTokenRecord(ctx, q, record.RefreshToken); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("session: commit full session transaction: %w", err)
	}
	return nil
}

// CreatePartialSession writes a partial MFA session and its verified factors.
func (s *SQLStore) CreatePartialSession(ctx context.Context, record PartialSessionRecord) error {
	if err := s.ready(); err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("session: begin partial session transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.queries.WithTx(tx)
	if err := createSessionRecord(ctx, q, record.Session, record.UserAgent); err != nil {
		return err
	}
	for _, factor := range record.Factors {
		if err := createFactorRecord(ctx, q, factor); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("session: commit partial session transaction: %w", err)
	}
	return nil
}

func (s *SQLStore) ready() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session sql store is nil", nil)
	}
	if s.db == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session sql store db is nil", nil)
	}
	if s.queries == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session sql store queries are nil", nil)
	}
	return nil
}

type sessionQueries interface {
	CreateRefreshToken(context.Context, sqlc.CreateRefreshTokenParams) (sqlc.RefreshToken, error)
	CreateSession(context.Context, sqlc.CreateSessionParams) (sqlc.Session, error)
	CreateSessionFactor(context.Context, sqlc.CreateSessionFactorParams) (sqlc.SessionFactor, error)
	UpsertSessionUserAgent(context.Context, sqlc.UpsertSessionUserAgentParams) (sqlc.SessionUserAgent, error)
}

func createSessionRecord(ctx context.Context, q sessionQueries, record SessionRecord, userAgent UserAgentRecord) error {
	if record.ID.IsZero() || record.AccountID.IsZero() || record.Kind == "" || record.Status == "" || record.ExpiresAt.IsZero() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "session id, account, kind, status, and expiry are required", nil)
	}
	if userAgent.FingerprintID != "" {
		headers := userAgent.Headers
		if len(headers) == 0 {
			headers = json.RawMessage(`{}`)
		}
		ip, err := optionalAddr(userAgent.IP)
		if err != nil {
			return err
		}
		if _, err := q.UpsertSessionUserAgent(ctx, sqlc.UpsertSessionUserAgentParams{
			FingerprintID: userAgent.FingerprintID,
			Ip:            ip,
			Description:   userAgent.Description,
			Headers:       append([]byte(nil), headers...),
		}); err != nil {
			return fmt.Errorf("session: upsert user agent: %w", err)
		}
	}

	ip, err := optionalAddr(record.IP)
	if err != nil {
		return err
	}
	_, err = q.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:          sessionIDToPG(record.ID),
		AccountID:   accountIDToPG(record.AccountID),
		ClientID:    clientIDToPG(record.ClientID),
		Kind:        record.Kind,
		Status:      record.Status,
		TokenID:     optionalString(record.TokenID),
		UserAgentID: optionalString(record.UserAgentID),
		Ip:          ip,
		ExpiresAt:   timeToTimestamptz(record.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("session: create session: %w", err)
	}
	return nil
}

func createFactorRecord(ctx context.Context, q sessionQueries, factor FactorRecord) error {
	if factor.SessionID.IsZero() || !factor.Kind.Valid() || factor.VerifiedAt.IsZero() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "session factor id, kind, and verification time are required", nil)
	}
	metadata := factor.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	_, err := q.CreateSessionFactor(ctx, sqlc.CreateSessionFactorParams{
		SessionID:        sessionIDToPG(factor.SessionID),
		FactorKind:       factor.Kind.String(),
		ChallengeBinding: factor.ChallengeBinding,
		VerifiedAt:       timeToTimestamptz(factor.VerifiedAt),
		Metadata:         append([]byte(nil), metadata...),
	})
	if err != nil {
		return fmt.Errorf("session: create session factor: %w", err)
	}
	return nil
}

func createRefreshTokenRecord(ctx context.Context, q sessionQueries, token RefreshTokenRecord) error {
	if token.ID == uuid.Nil || token.SessionID.IsZero() || len(token.TokenHash) == 0 || token.ExpiresAt.IsZero() || token.AbsoluteExpiresAt.IsZero() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "refresh token id, session, hash, and expiry are required", nil)
	}
	_, err := q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:                uuidToPG(token.ID),
		SessionID:         sessionIDToPG(token.SessionID),
		ClientID:          clientIDToPG(token.ClientID),
		TokenHash:         append([]byte(nil), token.TokenHash...),
		Scopes:            append([]string(nil), token.Scopes...),
		ExpiresAt:         timeToTimestamptz(token.ExpiresAt),
		AbsoluteExpiresAt: timeToTimestamptz(token.AbsoluteExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("session: create refresh token: %w", err)
	}
	return nil
}

func optionalAddr(value string) (*netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "session ip is malformed", err)
	}
	return &addr, nil
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: id != uuid.Nil}
}

func accountIDToPG(id account.AccountID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func sessionIDToPG(id account.SessionID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func clientIDToPG(id account.ClientID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func timeToTimestamptz(t time.Time) pgtype.Timestamptz {
	t = account.NormalizeTimestamp(t)
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	v := value
	return &v
}
