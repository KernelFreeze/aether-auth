package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

type credentialManagementQueries interface {
	CreateCredential(context.Context, sqlc.CreateCredentialParams) (sqlc.Credential, error)
	GetCredentialByIDForAccount(context.Context, sqlc.GetCredentialByIDForAccountParams) (sqlc.Credential, error)
	GetCredentialByProviderSubject(context.Context, sqlc.GetCredentialByProviderSubjectParams) (sqlc.Credential, error)
	GetCredentialPayload(context.Context, pgtype.UUID) (sqlc.CredentialPayload, error)
	ListCredentialsByAccount(context.Context, pgtype.UUID) ([]sqlc.Credential, error)
	RevokeCredentialForAccount(context.Context, sqlc.RevokeCredentialForAccountParams) (sqlc.Credential, error)
	UpdateCredentialStateForAccount(context.Context, sqlc.UpdateCredentialStateForAccountParams) (sqlc.Credential, error)
	UpsertCredentialPayload(context.Context, sqlc.UpsertCredentialPayloadParams) (sqlc.CredentialPayload, error)
}

// SQLCredentialStore persists account credentials with sqlc.
type SQLCredentialStore struct {
	queries credentialManagementQueries
}

var _ CredentialStore = (*SQLCredentialStore)(nil)

// NewSQLCredentialStore builds a credential store backed by sqlc queries.
func NewSQLCredentialStore(queries sqlc.Querier) *SQLCredentialStore {
	return &SQLCredentialStore{queries: queries}
}

// ProviderSubjectExists reports whether an active OIDC credential already uses
// provider and externalSubject.
func (s *SQLCredentialStore) ProviderSubjectExists(ctx context.Context, provider, externalSubject string) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	_, err := s.queries.GetCredentialByProviderSubject(ctx, sqlc.GetCredentialByProviderSubjectParams{
		Kind:            CredentialKindOIDC.String(),
		Provider:        optionalCredentialString(provider),
		ExternalSubject: optionalCredentialString(externalSubject),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapCredentialStoreError("check provider subject", err)
	}
	return true, nil
}

// CreateCredential inserts a credential and its encrypted payload when present.
func (s *SQLCredentialStore) CreateCredential(ctx context.Context, draft CredentialDraft) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if draft.ID.IsZero() || draft.AccountID.IsZero() || !draft.Kind.Valid() {
		return Credential{}, ErrInvalidCredential
	}

	row, err := s.queries.CreateCredential(ctx, sqlc.CreateCredentialParams{
		ID:              credentialIDToPG(draft.ID),
		AccountID:       accountIDToPG(draft.AccountID),
		Kind:            draft.Kind.String(),
		Provider:        optionalCredentialString(draft.Provider),
		ExternalSubject: optionalCredentialString(draft.ExternalSubject),
		DisplayName:     draft.DisplayName,
		Verified:        draft.Verified,
	})
	if err != nil {
		return Credential{}, mapCredentialStoreError("create credential", err)
	}
	if !draft.Payload.Empty() {
		if err := s.upsertPayload(ctx, row.ID, draft.Payload); err != nil {
			return Credential{}, err
		}
	}
	return s.credentialWithPayload(ctx, row)
}

// GetCredential returns one active credential for accountID.
func (s *SQLCredentialStore) GetCredential(ctx context.Context, accountID AccountID, credentialID CredentialID) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	row, err := s.queries.GetCredentialByIDForAccount(ctx, sqlc.GetCredentialByIDForAccountParams{
		ID:        credentialIDToPG(credentialID),
		AccountID: accountIDToPG(accountID),
	})
	if err != nil {
		return Credential{}, mapCredentialStoreError("get credential", err)
	}
	return s.credentialWithPayload(ctx, row)
}

// ListCredentials returns active credentials for accountID without payloads.
func (s *SQLCredentialStore) ListCredentials(ctx context.Context, accountID AccountID) ([]Credential, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	rows, err := s.queries.ListCredentialsByAccount(ctx, accountIDToPG(accountID))
	if err != nil {
		return nil, mapCredentialStoreError("list credentials", err)
	}
	credentials := make([]Credential, 0, len(rows))
	for _, row := range rows {
		credentials = append(credentials, credentialFromSQL(row))
	}
	return credentials, nil
}

// UpdateCredential updates active credential state and replaces the encrypted
// payload when provided.
func (s *SQLCredentialStore) UpdateCredential(ctx context.Context, update CredentialUpdate) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	row, err := s.queries.UpdateCredentialStateForAccount(ctx, sqlc.UpdateCredentialStateForAccountParams{
		ID:         credentialIDToPG(update.CredentialID),
		AccountID:  accountIDToPG(update.AccountID),
		Verified:   update.Verified,
		LastUsedAt: optionalCredentialTimestamptz(update.LastUsedAt),
	})
	if err != nil {
		return Credential{}, mapCredentialStoreError("update credential", err)
	}
	if update.Payload != nil && !update.Payload.Empty() {
		if err := s.upsertPayload(ctx, row.ID, *update.Payload); err != nil {
			return Credential{}, err
		}
	}
	return s.credentialWithPayload(ctx, row)
}

// RemoveCredential revokes one credential while preserving at least one active
// credential for the account.
func (s *SQLCredentialStore) RemoveCredential(ctx context.Context, accountID AccountID, credentialID CredentialID, revokedAt time.Time) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	rows, err := s.queries.ListCredentialsByAccount(ctx, accountIDToPG(accountID))
	if err != nil {
		return Credential{}, mapCredentialStoreError("list credentials before removal", err)
	}
	found := false
	for _, row := range rows {
		if credentialIDFromPG(row.ID) == credentialID {
			found = true
			break
		}
	}
	if !found {
		return Credential{}, ErrCredentialNotFound
	}
	if len(rows) <= 1 {
		return Credential{}, ErrLastCredential
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}

	row, err := s.queries.RevokeCredentialForAccount(ctx, sqlc.RevokeCredentialForAccountParams{
		ID:        credentialIDToPG(credentialID),
		AccountID: accountIDToPG(accountID),
		RevokedAt: timeToTimestamptz(revokedAt),
	})
	if err != nil {
		return Credential{}, mapCredentialStoreError("remove credential", err)
	}
	return s.credentialWithPayload(ctx, row)
}

func (s *SQLCredentialStore) ready() error {
	if s == nil || s.queries == nil {
		return errors.New("account: credential store is nil")
	}
	return nil
}

func (s *SQLCredentialStore) credentialWithPayload(ctx context.Context, row sqlc.Credential) (Credential, error) {
	credential := credentialFromSQL(row)
	payload, err := s.queries.GetCredentialPayload(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential, nil
	}
	if err != nil {
		return Credential{}, mapCredentialStoreError("get credential payload", err)
	}
	credential.Payload = credentialPayloadFromSQL(payload)
	return credential, nil
}

func (s *SQLCredentialStore) upsertPayload(ctx context.Context, credentialID pgtype.UUID, payload CredentialPayload) error {
	if payload.Algorithm == "" || payload.KeyRef == "" || len(payload.Ciphertext) == 0 {
		return ErrInvalidCredential
	}
	aad := append([]byte(nil), payload.AAD...)
	if len(aad) == 0 {
		aad = []byte(`{}`)
	}
	version := payload.Version
	if version == 0 {
		version = credentialPayloadVersion
	}
	_, err := s.queries.UpsertCredentialPayload(ctx, sqlc.UpsertCredentialPayloadParams{
		CredentialID: credentialID,
		Algorithm:    payload.Algorithm,
		KeyRef:       payload.KeyRef,
		Nonce:        append([]byte(nil), payload.Nonce...),
		Ciphertext:   append([]byte(nil), payload.Ciphertext...),
		Aad:          aad,
		Version:      version,
	})
	return mapCredentialStoreError("upsert credential payload", err)
}

func credentialFromSQL(row sqlc.Credential) Credential {
	return Credential{
		ID:              credentialIDFromPG(row.ID),
		AccountID:       accountIDFromPG(row.AccountID),
		Kind:            CredentialKind(row.Kind),
		Provider:        stringFromPointer(row.Provider),
		ExternalSubject: stringFromPointer(row.ExternalSubject),
		DisplayName:     row.DisplayName,
		Verified:        row.Verified,
		CreatedAt:       timestamptzToTime(row.CreatedAt),
		UpdatedAt:       timestamptzToTime(row.UpdatedAt),
		LastUsedAt:      timestamptzToTime(row.LastUsedAt),
		RevokedAt:       timestamptzToTime(row.RevokedAt),
	}
}

func credentialPayloadFromSQL(row sqlc.CredentialPayload) CredentialPayload {
	return CredentialPayload{
		Algorithm:  row.Algorithm,
		KeyRef:     row.KeyRef,
		Nonce:      append([]byte(nil), row.Nonce...),
		Ciphertext: append([]byte(nil), row.Ciphertext...),
		AAD:        append([]byte(nil), row.Aad...),
		Version:    row.Version,
	}
}

func mapCredentialStoreError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("account: %s: %w", action, ErrCredentialNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("account: %s: %w", action, ErrCredentialAlreadyExists)
		case "23514":
			return fmt.Errorf("account: %s: %w", action, ErrInvalidCredential)
		}
	}
	return fmt.Errorf("account: %s: %w", action, err)
}

func credentialIDToPG(id CredentialID) pgtype.UUID {
	return uuidToPG(id.UUID())
}

func credentialIDFromPG(id pgtype.UUID) CredentialID {
	return CredentialID(uuidFromPG(id))
}

func optionalCredentialString(value string) *string {
	if value == "" {
		return nil
	}
	v := value
	return &v
}

func optionalCredentialTimestamptz(t time.Time) pgtype.Timestamptz {
	return timeToTimestamptz(t)
}

func stringFromPointer(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
