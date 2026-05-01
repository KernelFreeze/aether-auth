package account

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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type registrationDB interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}

// SQLRegistrationStore persists account registration records with sqlc.
type SQLRegistrationStore struct {
	db      registrationDB
	queries *sqlc.Queries
}

var _ RegistrationStore = (*SQLRegistrationStore)(nil)

// NewSQLRegistrationStore builds a registration store backed by pgx.
func NewSQLRegistrationStore(db registrationDB) *SQLRegistrationStore {
	var queries *sqlc.Queries
	if db != nil {
		queries = sqlc.New(db)
	}
	return &SQLRegistrationStore{db: db, queries: queries}
}

// UsernameExists reports whether a normalized username is already present.
func (s *SQLRegistrationStore) UsernameExists(ctx context.Context, usernameNormalized string) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	_, err := s.queries.GetAccountByUsername(ctx, usernameNormalized)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapRegistrationStoreError("check username", err)
	}
	return true, nil
}

// EmailExists reports whether a normalized email is already present.
func (s *SQLRegistrationStore) EmailExists(ctx context.Context, emailNormalized string) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	_, err := s.queries.GetAccountByEmail(ctx, emailNormalized)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapRegistrationStoreError("check email", err)
	}
	return true, nil
}

// CreateRegistration creates the account and primary email in one transaction.
func (s *SQLRegistrationStore) CreateRegistration(ctx context.Context, draft AccountRegistrationDraft) (RegisteredAccount, error) {
	if err := s.ready(); err != nil {
		return RegisteredAccount{}, err
	}
	if draft.AccountID.IsZero() || draft.EmailID == uuid.Nil || draft.UsernameNormalized == "" || draft.EmailNormalized == "" {
		return RegisteredAccount{}, errors.New("account: registration draft is incomplete")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return RegisteredAccount{}, mapRegistrationStoreError("begin registration transaction", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := s.queries.WithTx(tx)
	accountRow, err := queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		ID:                 accountIDToPG(draft.AccountID),
		Username:           draft.Username,
		UsernameNormalized: draft.UsernameNormalized,
		DisplayName:        draft.DisplayName,
		Disabled:           false,
		MfaRequired:        false,
		LockedUntil:        pgtype.Timestamptz{},
		Metadata:           draft.AccountMetadataJSON,
	})
	if err != nil {
		return RegisteredAccount{}, mapRegistrationStoreError("create account", err)
	}

	emailRow, err := queries.CreateEmail(ctx, sqlc.CreateEmailParams{
		ID:                uuidToPG(draft.EmailID),
		AccountID:         accountRow.ID,
		Address:           draft.EmailAddress,
		AddressNormalized: draft.EmailNormalized,
		Verified:          draft.EmailVerified,
		IsPrimary:         true,
		VerifiedAt:        timeToTimestamptz(draft.EmailVerifiedAt),
	})
	if err != nil {
		return RegisteredAccount{}, mapRegistrationStoreError("create primary email", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return RegisteredAccount{}, mapRegistrationStoreError("commit registration transaction", err)
	}
	return registeredAccountFromSQL(accountRow, emailRow), nil
}

func (s *SQLRegistrationStore) ready() error {
	if s == nil || s.db == nil || s.queries == nil {
		return errors.New("account: registration store is nil")
	}
	return nil
}

type registrationAuditQueries interface {
	AppendAuditEvent(context.Context, sqlc.AppendAuditEventParams) (sqlc.AuditEvent, error)
}

// SQLRegistrationAuditWriter appends registration events to the audit table.
type SQLRegistrationAuditWriter struct {
	queries registrationAuditQueries
}

var _ RegistrationAuditWriter = (*SQLRegistrationAuditWriter)(nil)

// NewSQLRegistrationAuditWriter builds an audit writer backed by sqlc.
func NewSQLRegistrationAuditWriter(queries sqlc.Querier) *SQLRegistrationAuditWriter {
	return &SQLRegistrationAuditWriter{queries: queries}
}

// WriteRegistrationAuditEvent appends one registration audit event.
func (w *SQLRegistrationAuditWriter) WriteRegistrationAuditEvent(ctx context.Context, event RegistrationAuditEvent) error {
	if w == nil || w.queries == nil {
		return errors.New("account: registration audit writer is nil")
	}
	eventType := event.Type
	if eventType == "" {
		eventType = AuditEventRegistrationAttempted
	}

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("account: generate audit event id: %w", err)
	}
	attributes := event.Attributes
	if attributes == nil {
		attributes = map[string]string{}
	}
	encodedAttributes, err := json.Marshal(attributes)
	if err != nil {
		return fmt.Errorf("account: marshal registration audit attributes: %w", err)
	}
	ip, err := optionalRegistrationAddr(event.IP)
	if err != nil {
		return err
	}
	occurredAt := NormalizeTimestamp(event.OccurredAt)
	if occurredAt.IsZero() {
		occurredAt = NormalizeTimestamp(time.Now())
	}

	_, err = w.queries.AppendAuditEvent(ctx, sqlc.AppendAuditEventParams{
		ID:         uuidToPG(id),
		EventType:  eventType,
		AccountID:  accountIDToPG(event.AccountID),
		RequestID:  event.RequestID,
		Ip:         ip,
		UserAgent:  event.UserAgent,
		OccurredAt: timeToTimestamptz(occurredAt),
		Attributes: encodedAttributes,
	})
	return mapRegistrationStoreError("append registration audit event", err)
}

func registeredAccountFromSQL(accountRow sqlc.Account, emailRow sqlc.Email) RegisteredAccount {
	return RegisteredAccount{
		ID:                 accountIDFromPG(accountRow.ID),
		EmailID:            uuidFromPG(emailRow.ID),
		Username:           accountRow.Username,
		UsernameNormalized: accountRow.UsernameNormalized,
		DisplayName:        accountRow.DisplayName,
		EmailAddress:       emailRow.Address,
		EmailNormalized:    emailRow.AddressNormalized,
		EmailVerified:      emailRow.Verified,
		EmailVerifiedAt:    timestamptzToTime(emailRow.VerifiedAt),
		CreatedAt:          timestamptzToTime(accountRow.CreatedAt),
	}
}

func mapRegistrationStoreError(action string, err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("account: %s: %w", action, ErrRegistrationIdentityTaken)
	}
	return fmt.Errorf("account: %s: %w", action, err)
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

func accountIDToPG(id AccountID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func accountIDFromPG(id pgtype.UUID) AccountID {
	if !id.Valid {
		return AccountID(uuid.Nil)
	}
	return AccountID(uuid.UUID(id.Bytes))
}

func timeToTimestamptz(t time.Time) pgtype.Timestamptz {
	t = NormalizeTimestamp(t)
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}

func timestamptzToTime(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return NormalizeTimestamp(t.Time)
}

func optionalRegistrationAddr(value string) (*netip.Addr, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return nil, fmt.Errorf("account: registration audit ip is malformed: %w", err)
	}
	return &addr, nil
}
