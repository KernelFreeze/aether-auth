package session

import (
	"context"
	"encoding/json"
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

// RotateRefreshToken marks the presented refresh token as used, creates its
// replacement, and revokes the token family if reuse is detected.
func (s *SQLStore) RotateRefreshToken(ctx context.Context, rotation RefreshTokenRotation) (RefreshTokenRotationResult, error) {
	if err := s.ready(); err != nil {
		return RefreshTokenRotationResult{}, err
	}
	if len(rotation.TokenHash) == 0 || rotation.NewRefreshTokenID == uuid.Nil || len(rotation.NewTokenHash) == 0 {
		return RefreshTokenRotationResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "refresh rotation token hashes and id are required", nil)
	}
	now := account.NormalizeTimestamp(rotation.RotatedAt)
	if now.IsZero() {
		now = account.NormalizeTimestamp(time.Now())
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return RefreshTokenRotationResult{}, fmt.Errorf("session: begin refresh rotation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := s.queries.WithTx(tx)
	current, err := q.GetRefreshTokenByHash(ctx, rotation.TokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshTokenRotationResult{}, auth.ErrInvalidCredentials
	}
	if err != nil {
		return RefreshTokenRotationResult{}, fmt.Errorf("session: lookup refresh token: %w", err)
	}
	sessionRow, err := q.GetSessionByID(ctx, current.SessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshTokenRotationResult{}, auth.ErrInvalidCredentials
	}
	if err != nil {
		return RefreshTokenRotationResult{}, fmt.Errorf("session: lookup refresh session: %w", err)
	}

	if current.RotatedAt.Valid {
		if err := revokeRefreshFamily(ctx, q, current.ID, current.SessionID, now); err != nil {
			return RefreshTokenRotationResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return RefreshTokenRotationResult{}, fmt.Errorf("session: commit refresh reuse revocation: %w", err)
		}
		return RefreshTokenRotationResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "refresh token has already been used", nil)
	}
	if current.RevokedAt.Valid || !refreshTokenUsable(current, sessionRow, now) {
		return RefreshTokenRotationResult{}, auth.ErrInvalidCredentials
	}

	_, err = q.RotateRefreshToken(ctx, sqlc.RotateRefreshTokenParams{
		ID:        current.ID,
		RotatedAt: timeToTimestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if revokeErr := revokeRefreshFamily(ctx, q, current.ID, current.SessionID, now); revokeErr != nil {
			return RefreshTokenRotationResult{}, revokeErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return RefreshTokenRotationResult{}, fmt.Errorf("session: commit refresh reuse revocation: %w", commitErr)
		}
		return RefreshTokenRotationResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "refresh token has already been used", nil)
	}
	if err != nil {
		return RefreshTokenRotationResult{}, fmt.Errorf("session: rotate refresh token: %w", err)
	}

	newToken := RefreshTokenRecord{
		ID:                rotation.NewRefreshTokenID,
		SessionID:         sessionIDFromPG(current.SessionID),
		ParentID:          uuidFromPG(current.ID),
		ClientID:          clientIDFromPG(current.ClientID),
		TokenHash:         append([]byte(nil), rotation.NewTokenHash...),
		Scopes:            append([]string(nil), current.Scopes...),
		ExpiresAt:         nextRefreshExpiry(now, rotation.RefreshSliding, timestamptzToTime(current.AbsoluteExpiresAt), timestamptzToTime(sessionRow.ExpiresAt)),
		AbsoluteExpiresAt: timestamptzToTime(current.AbsoluteExpiresAt),
	}
	if err := createRefreshTokenRecord(ctx, q, newToken); err != nil {
		return RefreshTokenRotationResult{}, err
	}
	factorRows, err := q.ListSessionFactors(ctx, current.SessionID)
	if err != nil {
		return RefreshTokenRotationResult{}, fmt.Errorf("session: list refresh session factors: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return RefreshTokenRotationResult{}, fmt.Errorf("session: commit refresh rotation transaction: %w", err)
	}
	return RefreshTokenRotationResult{
		Session:      sessionRecordFromSQL(sessionRow),
		Factors:      factorRecordsFromSQL(factorRows),
		RefreshToken: newToken,
	}, nil
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

type refreshRotationQueries interface {
	sessionQueries
	GetRefreshTokenByHash(context.Context, []byte) (sqlc.RefreshToken, error)
	GetSessionByID(context.Context, pgtype.UUID) (sqlc.Session, error)
	ListSessionFactors(context.Context, pgtype.UUID) ([]sqlc.SessionFactor, error)
	RevokeRefreshTokenChain(context.Context, sqlc.RevokeRefreshTokenChainParams) ([]sqlc.RefreshToken, error)
	RevokeSession(context.Context, sqlc.RevokeSessionParams) (sqlc.Session, error)
	RotateRefreshToken(context.Context, sqlc.RotateRefreshTokenParams) (sqlc.RefreshToken, error)
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
		ParentID:          uuidToPG(token.ParentID),
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

func revokeRefreshFamily(ctx context.Context, q refreshRotationQueries, tokenID, sessionID pgtype.UUID, now time.Time) error {
	if _, err := q.RevokeRefreshTokenChain(ctx, sqlc.RevokeRefreshTokenChainParams{
		RootID:    tokenID,
		RevokedAt: timeToTimestamptz(now),
	}); err != nil {
		return fmt.Errorf("session: revoke refresh token chain: %w", err)
	}
	if _, err := q.RevokeSession(ctx, sqlc.RevokeSessionParams{
		ID:        sessionID,
		RevokedAt: timeToTimestamptz(now),
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("session: revoke refresh session: %w", err)
	}
	return nil
}

func refreshTokenUsable(token sqlc.RefreshToken, sessionRow sqlc.Session, now time.Time) bool {
	if sessionRow.Kind != sessionKindFull || sessionRow.Status != sessionStatusActive {
		return false
	}
	now = account.NormalizeTimestamp(now)
	for _, expiry := range []time.Time{
		timestamptzToTime(token.ExpiresAt),
		timestamptzToTime(token.AbsoluteExpiresAt),
		timestamptzToTime(sessionRow.ExpiresAt),
	} {
		if expiry.IsZero() || !now.Before(expiry) {
			return false
		}
	}
	return true
}

func nextRefreshExpiry(now time.Time, sliding time.Duration, absolute, sessionExpires time.Time) time.Time {
	if sliding <= 0 {
		sliding = defaultRefreshSliding
	}
	expiresAt := account.NormalizeTimestamp(now).Add(sliding)
	for _, capAt := range []time.Time{account.NormalizeTimestamp(absolute), account.NormalizeTimestamp(sessionExpires)} {
		if !capAt.IsZero() && expiresAt.After(capAt) {
			expiresAt = capAt
		}
	}
	return account.NormalizeTimestamp(expiresAt)
}

func sessionRecordFromSQL(row sqlc.Session) SessionRecord {
	return SessionRecord{
		ID:          sessionIDFromPG(row.ID),
		AccountID:   accountIDFromPG(row.AccountID),
		ClientID:    clientIDFromPG(row.ClientID),
		Kind:        row.Kind,
		Status:      row.Status,
		TokenID:     stringPtrValue(row.TokenID),
		UserAgentID: stringPtrValue(row.UserAgentID),
		IP:          addrPtrValue(row.Ip),
		ExpiresAt:   timestamptzToTime(row.ExpiresAt),
	}
}

func factorRecordsFromSQL(rows []sqlc.SessionFactor) []FactorRecord {
	records := make([]FactorRecord, 0, len(rows))
	for _, row := range rows {
		kind, err := account.ParseFactorKind(row.FactorKind)
		if err != nil {
			continue
		}
		records = append(records, FactorRecord{
			SessionID:        sessionIDFromPG(row.SessionID),
			Kind:             kind,
			ChallengeBinding: row.ChallengeBinding,
			VerifiedAt:       timestamptzToTime(row.VerifiedAt),
			Metadata:         append(json.RawMessage(nil), row.Metadata...),
		})
	}
	return records
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

func uuidFromPG(id pgtype.UUID) uuid.UUID {
	if !id.Valid {
		return uuid.Nil
	}
	return uuid.UUID(id.Bytes)
}

func accountIDToPG(id account.AccountID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func accountIDFromPG(id pgtype.UUID) account.AccountID {
	return account.AccountID(uuidFromPG(id))
}

func sessionIDToPG(id account.SessionID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func sessionIDFromPG(id pgtype.UUID) account.SessionID {
	return account.SessionID(uuidFromPG(id))
}

func clientIDToPG(id account.ClientID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func clientIDFromPG(id pgtype.UUID) account.ClientID {
	return account.ClientID(uuidFromPG(id))
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

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	v := value
	return &v
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func addrPtrValue(value *netip.Addr) string {
	if value == nil {
		return ""
	}
	return value.String()
}
