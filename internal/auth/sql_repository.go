package auth

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
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type accountQueries interface {
	GetAccountByEmail(context.Context, string) (sqlc.Account, error)
	GetAccountByID(context.Context, pgtype.UUID) (sqlc.Account, error)
	GetAccountByUsername(context.Context, string) (sqlc.Account, error)
}

type credentialQueries interface {
	CreateCredential(context.Context, sqlc.CreateCredentialParams) (sqlc.Credential, error)
	GetCredentialByAccountKindProvider(context.Context, sqlc.GetCredentialByAccountKindProviderParams) (sqlc.Credential, error)
	GetCredentialByID(context.Context, pgtype.UUID) (sqlc.Credential, error)
	GetCredentialByProviderSubject(context.Context, sqlc.GetCredentialByProviderSubjectParams) (sqlc.Credential, error)
	GetCredentialPayload(context.Context, pgtype.UUID) (sqlc.CredentialPayload, error)
	ListCredentialsByAccount(context.Context, pgtype.UUID) ([]sqlc.Credential, error)
	UpdateCredentialState(context.Context, sqlc.UpdateCredentialStateParams) (sqlc.Credential, error)
	UpsertCredentialPayload(context.Context, sqlc.UpsertCredentialPayloadParams) (sqlc.CredentialPayload, error)
}

type challengeQueries interface {
	ConsumeAuthChallenge(context.Context, sqlc.ConsumeAuthChallengeParams) (sqlc.AuthChallenge, error)
	CreateAuthChallenge(context.Context, sqlc.CreateAuthChallengeParams) (sqlc.AuthChallenge, error)
	DeleteExpiredAuthChallenges(context.Context, pgtype.Timestamptz) (int64, error)
	GetAuthChallenge(context.Context, string) (sqlc.AuthChallenge, error)
}

type auditQueries interface {
	AppendAuditEvent(context.Context, sqlc.AppendAuditEventParams) (sqlc.AuditEvent, error)
}

// SQLAccountRepository adapts sqlc account queries to the auth account
// repository contract.
type SQLAccountRepository struct {
	queries accountQueries
}

var _ AccountRepository = (*SQLAccountRepository)(nil)

// NewSQLAccountRepository builds an account repository backed by sqlc queries.
func NewSQLAccountRepository(queries sqlc.Querier) *SQLAccountRepository {
	return &SQLAccountRepository{queries: queries}
}

// LookupAccount returns the account matching the first supported lookup key.
func (r *SQLAccountRepository) LookupAccount(ctx context.Context, lookup AccountLookup) (AccountSnapshot, error) {
	if r == nil || r.queries == nil {
		return AccountSnapshot{}, NewServiceError(ErrorKindInternal, "account repository queries are nil", nil)
	}

	row, err := r.lookupAccount(ctx, lookup)
	if err != nil {
		return AccountSnapshot{}, err
	}
	return accountSnapshotFromSQL(row), nil
}

// AccountState returns the account state used by login policy checks.
func (r *SQLAccountRepository) AccountState(ctx context.Context, id account.AccountID) (AccountState, error) {
	if r == nil || r.queries == nil {
		return AccountState{}, NewServiceError(ErrorKindInternal, "account repository queries are nil", nil)
	}
	if id.IsZero() {
		return AccountState{}, NewServiceError(ErrorKindMalformedInput, "account id is required", nil)
	}

	row, err := r.queries.GetAccountByID(ctx, accountIDToPG(id))
	if err != nil {
		return AccountState{}, mapRepositoryError("lookup account state", err)
	}
	return AccountState{
		AccountID:   accountIDFromPG(row.ID),
		Disabled:    row.Disabled,
		LockedUntil: timestamptzToTime(row.LockedUntil),
		MFARequired: row.MfaRequired,
	}, nil
}

func (r *SQLAccountRepository) lookupAccount(ctx context.Context, lookup AccountLookup) (sqlc.Account, error) {
	switch {
	case !lookup.AccountID.IsZero():
		row, err := r.queries.GetAccountByID(ctx, accountIDToPG(lookup.AccountID))
		return row, mapRepositoryError("lookup account by id", err)
	case strings.TrimSpace(lookup.Username) != "":
		username := strings.ToLower(strings.TrimSpace(lookup.Username))
		row, err := r.queries.GetAccountByUsername(ctx, username)
		return row, mapRepositoryError("lookup account by username", err)
	case strings.TrimSpace(lookup.Email) != "":
		email := strings.ToLower(strings.TrimSpace(lookup.Email))
		row, err := r.queries.GetAccountByEmail(ctx, email)
		return row, mapRepositoryError("lookup account by email", err)
	default:
		return sqlc.Account{}, NewServiceError(ErrorKindMalformedInput, "account lookup key is required", nil)
	}
}

// CredentialPayloadConfig supplies encryption metadata for credential payload
// writes. Ciphertext comes from CredentialDraft and CredentialUpdate.
type CredentialPayloadConfig struct {
	Algorithm string
	KeyRef    string
	Nonce     []byte
	AAD       []byte
	Version   int32
}

// SQLCredentialRepository adapts sqlc credential queries to the auth
// credential repository contract.
type SQLCredentialRepository struct {
	queries       credentialQueries
	ids           IDGenerator
	payloadConfig CredentialPayloadConfig
}

var _ CredentialRepository = (*SQLCredentialRepository)(nil)

// NewSQLCredentialRepository builds a credential repository backed by sqlc
// queries.
func NewSQLCredentialRepository(queries sqlc.Querier, ids IDGenerator, payloadConfig CredentialPayloadConfig) *SQLCredentialRepository {
	return &SQLCredentialRepository{
		queries:       queries,
		ids:           ids,
		payloadConfig: payloadConfig,
	}
}

// LookupCredential returns one active credential matching lookup.
func (r *SQLCredentialRepository) LookupCredential(ctx context.Context, lookup CredentialLookup) (CredentialSnapshot, error) {
	if r == nil || r.queries == nil {
		return CredentialSnapshot{}, NewServiceError(ErrorKindInternal, "credential repository queries are nil", nil)
	}

	row, err := r.lookupCredential(ctx, lookup)
	if err != nil {
		return CredentialSnapshot{}, err
	}
	return r.snapshotWithPayload(ctx, row)
}

// CreateCredential stores a credential and its encrypted payload.
func (r *SQLCredentialRepository) CreateCredential(ctx context.Context, draft CredentialDraft) (CredentialSnapshot, error) {
	if r == nil || r.queries == nil {
		return CredentialSnapshot{}, NewServiceError(ErrorKindInternal, "credential repository queries are nil", nil)
	}
	if r.ids == nil {
		return CredentialSnapshot{}, NewServiceError(ErrorKindInternal, "credential repository id generator is nil", nil)
	}
	if draft.AccountID.IsZero() || !draft.Kind.Valid() {
		return CredentialSnapshot{}, NewServiceError(ErrorKindMalformedInput, "credential account and kind are required", nil)
	}

	id, err := r.ids.NewCredentialID()
	if err != nil {
		return CredentialSnapshot{}, fmt.Errorf("auth: create credential id: %w", err)
	}
	row, err := r.queries.CreateCredential(ctx, sqlc.CreateCredentialParams{
		ID:              credentialIDToPG(id),
		AccountID:       accountIDToPG(draft.AccountID),
		Kind:            draft.Kind.String(),
		Provider:        optionalString(draft.Provider),
		ExternalSubject: optionalString(draft.ExternalSubject),
		Verified:        draft.Verified,
	})
	if err != nil {
		return CredentialSnapshot{}, mapRepositoryError("create credential", err)
	}
	if len(draft.EncryptedPayload) > 0 {
		if err := r.upsertPayload(ctx, row.ID, draft.EncryptedPayload); err != nil {
			return CredentialSnapshot{}, err
		}
	}
	return r.snapshotWithPayload(ctx, row)
}

// UpdateCredential updates mutable credential fields and the encrypted payload.
func (r *SQLCredentialRepository) UpdateCredential(ctx context.Context, update CredentialUpdate) (CredentialSnapshot, error) {
	if r == nil || r.queries == nil {
		return CredentialSnapshot{}, NewServiceError(ErrorKindInternal, "credential repository queries are nil", nil)
	}
	if update.CredentialID.IsZero() {
		return CredentialSnapshot{}, NewServiceError(ErrorKindMalformedInput, "credential id is required", nil)
	}

	row, err := r.queries.UpdateCredentialState(ctx, sqlc.UpdateCredentialStateParams{
		ID:         credentialIDToPG(update.CredentialID),
		Verified:   update.Verified,
		LastUsedAt: optionalTimestamptz(update.LastUsedAt),
	})
	if err != nil {
		return CredentialSnapshot{}, mapRepositoryError("update credential", err)
	}
	if len(update.EncryptedPayload) > 0 {
		if err := r.upsertPayload(ctx, row.ID, update.EncryptedPayload); err != nil {
			return CredentialSnapshot{}, err
		}
	}
	return r.snapshotWithPayload(ctx, row)
}

// CanRemoveCredential reports whether removing credential would leave at least
// one active credential on the account.
func (r *SQLCredentialRepository) CanRemoveCredential(ctx context.Context, accountID account.AccountID, credentialID account.CredentialID) (bool, error) {
	if r == nil || r.queries == nil {
		return false, NewServiceError(ErrorKindInternal, "credential repository queries are nil", nil)
	}
	if accountID.IsZero() || credentialID.IsZero() {
		return false, NewServiceError(ErrorKindMalformedInput, "account id and credential id are required", nil)
	}

	rows, err := r.queries.ListCredentialsByAccount(ctx, accountIDToPG(accountID))
	if err != nil {
		return false, mapRepositoryError("list credentials for removal check", err)
	}
	found := false
	for _, row := range rows {
		if credentialIDFromPG(row.ID) == credentialID {
			found = true
			break
		}
	}
	return found && len(rows) > 1, nil
}

func (r *SQLCredentialRepository) lookupCredential(ctx context.Context, lookup CredentialLookup) (sqlc.Credential, error) {
	switch {
	case !lookup.CredentialID.IsZero():
		row, err := r.queries.GetCredentialByID(ctx, credentialIDToPG(lookup.CredentialID))
		return row, mapRepositoryError("lookup credential by id", err)
	case lookup.Kind.Valid() && lookup.Provider != "" && lookup.ExternalSubject != "":
		row, err := r.queries.GetCredentialByProviderSubject(ctx, sqlc.GetCredentialByProviderSubjectParams{
			Kind:            lookup.Kind.String(),
			Provider:        optionalString(lookup.Provider),
			ExternalSubject: optionalString(lookup.ExternalSubject),
		})
		return row, mapRepositoryError("lookup credential by provider subject", err)
	case !lookup.AccountID.IsZero() && lookup.Kind.Valid():
		row, err := r.queries.GetCredentialByAccountKindProvider(ctx, sqlc.GetCredentialByAccountKindProviderParams{
			AccountID: accountIDToPG(lookup.AccountID),
			Kind:      lookup.Kind.String(),
			Provider:  optionalString(lookup.Provider),
		})
		return row, mapRepositoryError("lookup credential by account kind provider", err)
	default:
		return sqlc.Credential{}, NewServiceError(ErrorKindMalformedInput, "credential lookup key is required", nil)
	}
}

func (r *SQLCredentialRepository) snapshotWithPayload(ctx context.Context, row sqlc.Credential) (CredentialSnapshot, error) {
	snapshot := credentialSnapshotFromSQL(row)
	payload, err := r.queries.GetCredentialPayload(ctx, row.ID)
	if err == nil {
		snapshot.EncryptedPayload = append([]byte(nil), payload.Ciphertext...)
		return snapshot, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, nil
	}
	return CredentialSnapshot{}, mapRepositoryError("lookup credential payload", err)
}

func (r *SQLCredentialRepository) upsertPayload(ctx context.Context, credentialID pgtype.UUID, ciphertext []byte) error {
	config := r.payloadConfig
	if config.Algorithm == "" || config.KeyRef == "" {
		return NewServiceError(ErrorKindMalformedInput, "credential payload algorithm and key ref are required", nil)
	}
	version := config.Version
	if version == 0 {
		version = 1
	}
	_, err := r.queries.UpsertCredentialPayload(ctx, sqlc.UpsertCredentialPayloadParams{
		CredentialID: credentialID,
		Algorithm:    config.Algorithm,
		KeyRef:       config.KeyRef,
		Nonce:        append([]byte(nil), config.Nonce...),
		Ciphertext:   append([]byte(nil), ciphertext...),
		Aad:          append([]byte(nil), config.AAD...),
		Version:      version,
	})
	return mapRepositoryError("upsert credential payload", err)
}

// SQLChallengeStore adapts sqlc auth challenge queries to ChallengeStore.
type SQLChallengeStore struct {
	queries challengeQueries
	clock   Clock
}

var _ ChallengeStore = (*SQLChallengeStore)(nil)

// NewSQLChallengeStore builds a challenge store backed by sqlc queries.
func NewSQLChallengeStore(queries sqlc.Querier, clock Clock) *SQLChallengeStore {
	return &SQLChallengeStore{queries: queries, clock: clock}
}

// SaveChallenge inserts a one-time auth challenge.
func (s *SQLChallengeStore) SaveChallenge(ctx context.Context, challenge StoredChallenge) error {
	if s == nil || s.queries == nil {
		return NewServiceError(ErrorKindInternal, "challenge store queries are nil", nil)
	}
	if challenge.ID == "" || challenge.Purpose == "" || challenge.SessionBinding == "" || challenge.ExpiresAt.IsZero() {
		return NewServiceError(ErrorKindMalformedInput, "challenge id, purpose, binding, and expiry are required", nil)
	}

	_, err := s.queries.CreateAuthChallenge(ctx, sqlc.CreateAuthChallengeParams{
		ID:             challenge.ID,
		Purpose:        string(challenge.Purpose),
		AccountID:      accountIDToPG(challenge.AccountID),
		CredentialID:   credentialIDToPG(challenge.CredentialID),
		Provider:       optionalString(challenge.Provider),
		SessionBinding: challenge.SessionBinding,
		RequestID:      challenge.RequestID,
		Payload:        append([]byte(nil), challenge.Payload...),
		ExpiresAt:      timeToTimestamptz(challenge.ExpiresAt),
	})
	return mapRepositoryError("save challenge", err)
}

// ConsumeChallenge atomically consumes a valid, unexpired challenge.
func (s *SQLChallengeStore) ConsumeChallenge(ctx context.Context, lookup ChallengeLookup) (StoredChallenge, error) {
	if s == nil || s.queries == nil {
		return StoredChallenge{}, NewServiceError(ErrorKindInternal, "challenge store queries are nil", nil)
	}
	if lookup.ID == "" || lookup.Purpose == "" || lookup.SessionBinding == "" {
		return StoredChallenge{}, NewServiceError(ErrorKindMalformedInput, "challenge id, purpose, and binding are required", nil)
	}

	existing, err := s.queries.GetAuthChallenge(ctx, lookup.ID)
	if err != nil {
		return StoredChallenge{}, mapRepositoryError("lookup challenge", err)
	}
	if existing.Purpose != string(lookup.Purpose) || existing.SessionBinding != lookup.SessionBinding || stringPtrValue(existing.Provider) != lookup.Provider {
		return StoredChallenge{}, NewServiceError(ErrorKindMalformedInput, "challenge lookup does not match stored challenge", nil)
	}
	if existing.ConsumedAt.Valid {
		return StoredChallenge{}, ErrReplayedChallenge
	}
	if account.IsExpired(s.now(), timestamptzToTime(existing.ExpiresAt)) {
		return StoredChallenge{}, ErrExpiredChallenge
	}

	row, err := s.queries.ConsumeAuthChallenge(ctx, sqlc.ConsumeAuthChallengeParams{
		ID:         lookup.ID,
		ConsumedAt: timeToTimestamptz(s.now()),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StoredChallenge{}, ErrReplayedChallenge
		}
		return StoredChallenge{}, mapRepositoryError("consume challenge", err)
	}
	return storedChallengeFromSQL(row), nil
}

// DeleteExpiredChallenges removes expired challenge records.
func (s *SQLChallengeStore) DeleteExpiredChallenges(ctx context.Context, now time.Time) error {
	if s == nil || s.queries == nil {
		return NewServiceError(ErrorKindInternal, "challenge store queries are nil", nil)
	}
	_, err := s.queries.DeleteExpiredAuthChallenges(ctx, timeToTimestamptz(now))
	return mapRepositoryError("delete expired challenges", err)
}

func (s *SQLChallengeStore) now() time.Time {
	if s.clock == nil {
		return account.NormalizeTimestamp(time.Now())
	}
	return account.NormalizeTimestamp(s.clock.Now())
}

// SQLAuditWriter adapts sqlc audit queries to AuditWriter.
type SQLAuditWriter struct {
	queries auditQueries
}

var _ AuditWriter = (*SQLAuditWriter)(nil)

// NewSQLAuditWriter builds an audit writer backed by sqlc queries.
func NewSQLAuditWriter(queries sqlc.Querier) *SQLAuditWriter {
	return &SQLAuditWriter{queries: queries}
}

// WriteAuditEvent appends a security audit event.
func (w *SQLAuditWriter) WriteAuditEvent(ctx context.Context, event AuditEvent) error {
	if w == nil || w.queries == nil {
		return NewServiceError(ErrorKindInternal, "audit writer queries are nil", nil)
	}
	if event.Type == "" {
		return NewServiceError(ErrorKindMalformedInput, "audit event type is required", nil)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("auth: generate audit event id: %w", err)
	}
	attributes, err := json.Marshal(event.Attributes)
	if err != nil {
		return fmt.Errorf("auth: marshal audit attributes: %w", err)
	}
	ip, err := optionalAddr(event.IP)
	if err != nil {
		return err
	}
	occurredAt := event.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}

	_, err = w.queries.AppendAuditEvent(ctx, sqlc.AppendAuditEventParams{
		ID:           uuidToPG(id),
		EventType:    event.Type,
		AccountID:    accountIDToPG(event.AccountID),
		CredentialID: credentialIDToPG(event.CredentialID),
		SessionID:    sessionIDToPG(event.SessionID),
		RequestID:    event.RequestID,
		Ip:           ip,
		UserAgent:    event.UserAgent,
		OccurredAt:   timeToTimestamptz(occurredAt),
		Attributes:   attributes,
	})
	return mapRepositoryError("append audit event", err)
}

func accountSnapshotFromSQL(row sqlc.Account) AccountSnapshot {
	return AccountSnapshot{
		ID:          accountIDFromPG(row.ID),
		Username:    row.Username,
		DisplayName: row.DisplayName,
		Disabled:    row.Disabled,
		LockedUntil: timestamptzToTime(row.LockedUntil),
		MFARequired: row.MfaRequired,
		UpdatedAt:   timestamptzToTime(row.UpdatedAt),
	}
}

func credentialSnapshotFromSQL(row sqlc.Credential) CredentialSnapshot {
	kind, err := account.ParseCredentialKind(row.Kind)
	if err != nil {
		kind = ""
	}
	return CredentialSnapshot{
		ID:              credentialIDFromPG(row.ID),
		AccountID:       accountIDFromPG(row.AccountID),
		Kind:            kind,
		Provider:        stringPtrValue(row.Provider),
		ExternalSubject: stringPtrValue(row.ExternalSubject),
		Verified:        row.Verified,
		CreatedAt:       timestamptzToTime(row.CreatedAt),
		UpdatedAt:       timestamptzToTime(row.UpdatedAt),
		LastUsedAt:      timestamptzToTime(row.LastUsedAt),
	}
}

func storedChallengeFromSQL(row sqlc.AuthChallenge) StoredChallenge {
	return StoredChallenge{
		ID:             row.ID,
		Purpose:        ChallengePurpose(row.Purpose),
		AccountID:      accountIDFromPG(row.AccountID),
		CredentialID:   credentialIDFromPG(row.CredentialID),
		Provider:       stringPtrValue(row.Provider),
		SessionBinding: row.SessionBinding,
		RequestID:      row.RequestID,
		Payload:        append([]byte(nil), row.Payload...),
		ExpiresAt:      timestamptzToTime(row.ExpiresAt),
		CreatedAt:      timestamptzToTime(row.CreatedAt),
	}
}

func mapRepositoryError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return NewServiceError(ErrorKindInvalidCredentials, action, err)
	}
	return fmt.Errorf("auth: %s: %w", action, err)
}

func uuidToPG(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: id != uuid.Nil}
}

func accountIDToPG(id account.AccountID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func credentialIDToPG(id account.CredentialID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func sessionIDToPG(id account.SessionID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func accountIDFromPG(id pgtype.UUID) account.AccountID {
	if !id.Valid {
		return account.AccountID(uuid.Nil)
	}
	return account.AccountID(uuid.UUID(id.Bytes))
}

func credentialIDFromPG(id pgtype.UUID) account.CredentialID {
	if !id.Valid {
		return account.CredentialID(uuid.Nil)
	}
	return account.CredentialID(uuid.UUID(id.Bytes))
}

func timeToTimestamptz(t time.Time) pgtype.Timestamptz {
	t = account.NormalizeTimestamp(t)
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}

func optionalTimestamptz(t time.Time) pgtype.Timestamptz {
	return timeToTimestamptz(t)
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

func optionalAddr(value string) (*netip.Addr, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return nil, NewServiceError(ErrorKindMalformedInput, "audit event ip is malformed", err)
	}
	return &addr, nil
}
