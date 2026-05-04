package webauthn

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type credentialDB interface {
	sqlc.DBTX
	Begin(context.Context) (pgx.Tx, error)
}

// CredentialStore persists WebAuthn credential material beside account
// credential rows.
type CredentialStore interface {
	CreateCredential(context.Context, Credential) (Credential, error)
	GetCredentialByKeyID(context.Context, []byte) (Credential, error)
	ListCredentials(context.Context, account.AccountID, string) ([]Credential, error)
	UpdateCredentialAssertion(context.Context, Credential) (Credential, error)
}

// SQLCredentialStore stores passkey material through sqlc queries.
type SQLCredentialStore struct {
	db      credentialDB
	queries *sqlc.Queries
}

var _ CredentialStore = (*SQLCredentialStore)(nil)

// NewSQLCredentialStore builds a WebAuthn credential store backed by sqlc.
func NewSQLCredentialStore(db credentialDB) *SQLCredentialStore {
	var queries *sqlc.Queries
	if db != nil {
		queries = sqlc.New(db)
	}
	return &SQLCredentialStore{db: db, queries: queries}
}

// CreateCredential inserts the generic credential row and WebAuthn material in
// one transaction.
func (s *SQLCredentialStore) CreateCredential(ctx context.Context, credential Credential) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if err := validateStoredCredential(credential); err != nil {
		return Credential{}, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Credential{}, fmt.Errorf("webauthn: begin credential create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	row, err := q.CreateCredential(ctx, sqlc.CreateCredentialParams{
		ID:          credentialIDToPG(credential.ID),
		AccountID:   accountIDToPG(credential.AccountID),
		Kind:        account.CredentialKindWebAuthn.String(),
		DisplayName: credential.DisplayName,
		Verified:    credential.Verified,
	})
	if err != nil {
		return Credential{}, mapStoreError("create credential row", err)
	}
	if _, err := q.CreateWebAuthnCredential(ctx, createWebAuthnCredentialParams(credential)); err != nil {
		return Credential{}, mapStoreError("create webauthn credential", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Credential{}, fmt.Errorf("webauthn: commit credential create: %w", err)
	}

	stored, err := s.GetCredentialByKeyID(ctx, credential.KeyID)
	if err != nil {
		return Credential{}, err
	}
	stored.CreatedAt = account.NormalizeTimestamp(row.CreatedAt.Time)
	return stored, nil
}

// GetCredentialByKeyID returns an active WebAuthn credential by browser key ID.
func (s *SQLCredentialStore) GetCredentialByKeyID(ctx context.Context, keyID []byte) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if len(keyID) == 0 {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn key id is required", nil)
	}
	row, err := s.queries.GetWebAuthnCredentialByKeyID(ctx, cloneBytes(keyID))
	if err != nil {
		return Credential{}, mapStoreError("get webauthn credential by key id", err)
	}
	return credentialFromSQL(row.Credential, row.WebauthnCredential), nil
}

// ListCredentials returns active WebAuthn credentials for an account. A blank
// relyingPartyID returns credentials for all relying parties.
func (s *SQLCredentialStore) ListCredentials(ctx context.Context, accountID account.AccountID, relyingPartyID string) ([]Credential, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if accountID.IsZero() {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn account id is required", nil)
	}
	rows, err := s.queries.ListWebAuthnCredentialsByAccount(ctx, sqlc.ListWebAuthnCredentialsByAccountParams{
		AccountID:      accountIDToPG(accountID),
		RelyingPartyID: relyingPartyID,
	})
	if err != nil {
		return nil, mapStoreError("list webauthn credentials", err)
	}
	credentials := make([]Credential, 0, len(rows))
	for _, row := range rows {
		credentials = append(credentials, credentialFromSQL(row.Credential, row.WebauthnCredential))
	}
	return credentials, nil
}

// UpdateCredentialAssertion stores assertion state after a successful passkey
// login.
func (s *SQLCredentialStore) UpdateCredentialAssertion(ctx context.Context, credential Credential) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if credential.ID.IsZero() || credential.AccountID.IsZero() {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn account and credential id are required", nil)
	}
	if credential.SignCount > math.MaxInt32 {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn sign count is too large", nil)
	}
	lastUsedAt := credential.LastUsedAt
	if lastUsedAt.IsZero() {
		lastUsedAt = time.Now()
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Credential{}, fmt.Errorf("webauthn: begin assertion update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.queries.WithTx(tx)

	if _, err := q.UpdateCredentialStateForAccount(ctx, sqlc.UpdateCredentialStateForAccountParams{
		ID:         credentialIDToPG(credential.ID),
		AccountID:  accountIDToPG(credential.AccountID),
		LastUsedAt: timeToTimestamptz(lastUsedAt),
	}); err != nil {
		return Credential{}, mapStoreError("update credential state", err)
	}
	if _, err := q.UpdateWebAuthnCredentialAssertion(ctx, sqlc.UpdateWebAuthnCredentialAssertionParams{
		CredentialID:            credentialIDToPG(credential.ID),
		SignCount:               int32(credential.SignCount),
		UserVerified:            credential.UserVerified,
		BackedUp:                credential.BackedUp,
		Transports:              transportsToStrings(credential.Transports),
		BackupEligible:          credential.BackupEligible,
		AuthenticatorAttachment: string(credential.AuthenticatorAttachment),
	}); err != nil {
		return Credential{}, mapStoreError("update webauthn credential assertion", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Credential{}, fmt.Errorf("webauthn: commit assertion update: %w", err)
	}

	row, err := s.queries.GetWebAuthnCredentialByCredentialID(ctx, credentialIDToPG(credential.ID))
	if err != nil {
		return Credential{}, mapStoreError("get updated webauthn credential", err)
	}
	return credentialFromSQL(row.Credential, row.WebauthnCredential), nil
}

func (s *SQLCredentialStore) ready() error {
	if s == nil || s.db == nil || s.queries == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn credential store is nil", nil)
	}
	return nil
}

func validateStoredCredential(credential Credential) error {
	switch {
	case credential.ID.IsZero(), credential.AccountID.IsZero():
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn account and credential id are required", nil)
	case len(credential.KeyID) == 0:
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn key id is required", nil)
	case len(credential.PublicKey) == 0:
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn public key is required", nil)
	case credential.RelyingPartyID == "":
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn relying party id is required", nil)
	case credential.SignCount > math.MaxInt32:
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn sign count is too large", nil)
	default:
		return nil
	}
}

func createWebAuthnCredentialParams(credential Credential) sqlc.CreateWebAuthnCredentialParams {
	return sqlc.CreateWebAuthnCredentialParams{
		CredentialID:            credentialIDToPG(credential.ID),
		KeyID:                   cloneBytes(credential.KeyID),
		PublicKey:               cloneBytes(credential.PublicKey),
		SignCount:               int32(credential.SignCount),
		RelyingPartyID:          credential.RelyingPartyID,
		Aaguid:                  cloneBytes(credential.AAGUID),
		AttestationType:         credential.AttestationType,
		UserVerified:            credential.UserVerified,
		BackedUp:                credential.BackedUp,
		Transports:              transportsToStrings(credential.Transports),
		BackupEligible:          credential.BackupEligible,
		AuthenticatorAttachment: string(credential.AuthenticatorAttachment),
	}
}

func credentialFromSQL(row sqlc.Credential, webauthnRow sqlc.WebauthnCredential) Credential {
	return Credential{
		ID:                      credentialIDFromPG(row.ID),
		AccountID:               accountIDFromPG(row.AccountID),
		KeyID:                   cloneBytes(webauthnRow.KeyID),
		PublicKey:               cloneBytes(webauthnRow.PublicKey),
		AttestationType:         webauthnRow.AttestationType,
		Transports:              transportsFromStrings(webauthnRow.Transports),
		AAGUID:                  cloneBytes(webauthnRow.Aaguid),
		SignCount:               uint32(webauthnRow.SignCount),
		RelyingPartyID:          webauthnRow.RelyingPartyID,
		UserVerified:            webauthnRow.UserVerified,
		BackupEligible:          webauthnRow.BackupEligible,
		BackedUp:                webauthnRow.BackedUp,
		AuthenticatorAttachment: AuthenticatorAttachment(webauthnRow.AuthenticatorAttachment),
		DisplayName:             row.DisplayName,
		Verified:                row.Verified,
		CreatedAt:               timestamptzToTime(row.CreatedAt),
		UpdatedAt:               timestamptzToTime(row.UpdatedAt),
		LastUsedAt:              timestamptzToTime(row.LastUsedAt),
	}
}

func mapStoreError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.NewServiceError(auth.ErrorKindInvalidCredentials, action, err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "23514", "23503":
			return auth.NewServiceError(auth.ErrorKindMalformedInput, action, err)
		}
	}
	return fmt.Errorf("webauthn: %s: %w", action, err)
}

func transportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	values := make([]string, 0, len(transports))
	for _, transport := range transports {
		if transport != "" {
			values = append(values, string(transport))
		}
	}
	return values
}

func transportsFromStrings(values []string) []protocol.AuthenticatorTransport {
	transports := make([]protocol.AuthenticatorTransport, 0, len(values))
	for _, value := range values {
		if value != "" {
			transports = append(transports, protocol.AuthenticatorTransport(value))
		}
	}
	return transports
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

func credentialIDToPG(id account.CredentialID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func credentialIDFromPG(id pgtype.UUID) account.CredentialID {
	return account.CredentialID(uuidFromPG(id))
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
