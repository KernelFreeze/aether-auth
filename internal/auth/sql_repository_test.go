package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

func TestSQLAccountRepositoryLookupAccountNormalizesUsername(t *testing.T) {
	ctx := context.Background()
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000001")
	updatedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	queries := &fakeSQLAccountQueries{
		account: sqlc.Account{
			ID:                 accountIDToPG(accountID),
			Username:           "Celeste",
			UsernameNormalized: "celeste",
			DisplayName:        "Celeste",
			MfaRequired:        true,
			UpdatedAt:          timeToTimestamptz(updatedAt),
		},
	}

	repo := &SQLAccountRepository{queries: queries}
	got, err := repo.LookupAccount(ctx, AccountLookup{Username: "  CELESTE  "})
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}

	if queries.username != "celeste" {
		t.Fatalf("username lookup = %q, want celeste", queries.username)
	}
	if got.ID != accountID || got.Username != "Celeste" || !got.MFARequired || !got.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("snapshot = %#v", got)
	}
}

func TestSQLCredentialRepositoryCreateStoresEncryptedPayload(t *testing.T) {
	ctx := context.Background()
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000002")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000000003")
	queries := &fakeSQLCredentialQueries{}
	repo := &SQLCredentialRepository{
		queries: queries,
		ids:     fakeIDGenerator{credentialID: credentialID},
		payloadConfig: CredentialPayloadConfig{
			Algorithm: "aes-256-gcm",
			KeyRef:    "env://AUTH_CREDENTIAL_KEY",
			Nonce:     []byte("nonce"),
			AAD:       []byte("aad"),
			Version:   2,
		},
	}

	got, err := repo.CreateCredential(ctx, CredentialDraft{
		AccountID:        accountID,
		Kind:             account.CredentialKindPassword,
		EncryptedPayload: []byte("ciphertext"),
		Verified:         true,
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	if queries.createArg.ID != credentialIDToPG(credentialID) {
		t.Fatalf("credential id = %v, want %v", queries.createArg.ID, credentialID)
	}
	if queries.payloadArg.Algorithm != "aes-256-gcm" || queries.payloadArg.KeyRef != "env://AUTH_CREDENTIAL_KEY" {
		t.Fatalf("payload metadata = %#v", queries.payloadArg)
	}
	if string(queries.payloadArg.Ciphertext) != "ciphertext" {
		t.Fatalf("payload ciphertext = %q, want ciphertext", queries.payloadArg.Ciphertext)
	}
	if got.ID != credentialID || got.AccountID != accountID || got.Kind != account.CredentialKindPassword {
		t.Fatalf("credential snapshot = %#v", got)
	}
	if string(got.EncryptedPayload) != "ciphertext" {
		t.Fatalf("snapshot payload = %q, want ciphertext", got.EncryptedPayload)
	}
}

func TestSQLCredentialRepositoryCanRemoveCredentialKeepsLastCredential(t *testing.T) {
	ctx := context.Background()
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000004")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000000005")
	queries := &fakeSQLCredentialQueries{
		listRows: []sqlc.Credential{{ID: credentialIDToPG(credentialID), AccountID: accountIDToPG(accountID)}},
	}
	repo := &SQLCredentialRepository{queries: queries}

	canRemove, err := repo.CanRemoveCredential(ctx, accountID, credentialID)
	if err != nil {
		t.Fatalf("can remove credential: %v", err)
	}
	if canRemove {
		t.Fatal("single active credential should not be removable")
	}
}

func TestSQLChallengeStoreConsumeChallengeRejectsExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	queries := &fakeSQLChallengeQueries{
		challenge: sqlc.AuthChallenge{
			ID:             "chal_123",
			Purpose:        string(ChallengePurposeWebAuthn),
			SessionBinding: "binding",
			Payload:        []byte("payload"),
			ExpiresAt:      timeToTimestamptz(now.Add(-time.Second)),
		},
	}
	store := &SQLChallengeStore{queries: queries, clock: fakeClock{now: now}}

	_, err := store.ConsumeChallenge(ctx, ChallengeLookup{
		ID:             "chal_123",
		Purpose:        ChallengePurposeWebAuthn,
		SessionBinding: "binding",
	})
	if !errors.Is(err, ErrExpiredChallenge) {
		t.Fatalf("consume error = %v, want expired challenge", err)
	}
	if queries.consumeCalled {
		t.Fatal("expired challenge should not be consumed")
	}
}

func TestSQLAuditWriterMarshalsAttributesAndIP(t *testing.T) {
	ctx := context.Background()
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000006")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	queries := &fakeSQLAuditQueries{}
	writer := &SQLAuditWriter{queries: queries}

	err := writer.WriteAuditEvent(ctx, AuditEvent{
		Type:       "auth.login.succeeded",
		AccountID:  accountID,
		RequestID:  "req_123",
		IP:         "2001:db8::1",
		UserAgent:  "test-agent",
		OccurredAt: now,
		Attributes: map[string]string{"method": "password"},
	})
	if err != nil {
		t.Fatalf("write audit event: %v", err)
	}

	if queries.arg.EventType != "auth.login.succeeded" || queries.arg.AccountID != accountIDToPG(accountID) {
		t.Fatalf("audit params = %#v", queries.arg)
	}
	if queries.arg.Ip == nil || *queries.arg.Ip != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("audit ip = %v, want 2001:db8::1", queries.arg.Ip)
	}
	var attrs map[string]string
	if err := json.Unmarshal(queries.arg.Attributes, &attrs); err != nil {
		t.Fatalf("unmarshal attributes: %v", err)
	}
	if attrs["method"] != "password" {
		t.Fatalf("attributes = %#v", attrs)
	}
}

type fakeSQLAccountQueries struct {
	account  sqlc.Account
	username string
}

func (q *fakeSQLAccountQueries) GetAccountByEmail(context.Context, string) (sqlc.Account, error) {
	return sqlc.Account{}, pgx.ErrNoRows
}

func (q *fakeSQLAccountQueries) GetAccountByID(context.Context, pgtype.UUID) (sqlc.Account, error) {
	return q.account, nil
}

func (q *fakeSQLAccountQueries) GetAccountByUsername(_ context.Context, username string) (sqlc.Account, error) {
	q.username = username
	return q.account, nil
}

type fakeSQLCredentialQueries struct {
	createArg  sqlc.CreateCredentialParams
	payloadArg sqlc.UpsertCredentialPayloadParams
	listRows   []sqlc.Credential
}

func (q *fakeSQLCredentialQueries) CreateCredential(_ context.Context, arg sqlc.CreateCredentialParams) (sqlc.Credential, error) {
	q.createArg = arg
	return sqlc.Credential{
		ID:        arg.ID,
		AccountID: arg.AccountID,
		Kind:      arg.Kind,
		Provider:  arg.Provider,
		Verified:  arg.Verified,
	}, nil
}

func (q *fakeSQLCredentialQueries) GetCredentialByAccountKindProvider(context.Context, sqlc.GetCredentialByAccountKindProviderParams) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeSQLCredentialQueries) GetCredentialByID(context.Context, pgtype.UUID) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeSQLCredentialQueries) GetCredentialByProviderSubject(context.Context, sqlc.GetCredentialByProviderSubjectParams) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeSQLCredentialQueries) GetCredentialPayload(context.Context, pgtype.UUID) (sqlc.CredentialPayload, error) {
	if len(q.payloadArg.Ciphertext) == 0 {
		return sqlc.CredentialPayload{}, pgx.ErrNoRows
	}
	return sqlc.CredentialPayload{Ciphertext: q.payloadArg.Ciphertext}, nil
}

func (q *fakeSQLCredentialQueries) ListCredentialsByAccount(context.Context, pgtype.UUID) ([]sqlc.Credential, error) {
	return q.listRows, nil
}

func (q *fakeSQLCredentialQueries) UpdateCredentialState(context.Context, sqlc.UpdateCredentialStateParams) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeSQLCredentialQueries) UpsertCredentialPayload(_ context.Context, arg sqlc.UpsertCredentialPayloadParams) (sqlc.CredentialPayload, error) {
	q.payloadArg = arg
	return sqlc.CredentialPayload{Ciphertext: arg.Ciphertext}, nil
}

type fakeSQLChallengeQueries struct {
	challenge     sqlc.AuthChallenge
	consumeCalled bool
}

func (q *fakeSQLChallengeQueries) ConsumeAuthChallenge(context.Context, sqlc.ConsumeAuthChallengeParams) (sqlc.AuthChallenge, error) {
	q.consumeCalled = true
	return q.challenge, nil
}

func (q *fakeSQLChallengeQueries) CreateAuthChallenge(context.Context, sqlc.CreateAuthChallengeParams) (sqlc.AuthChallenge, error) {
	return sqlc.AuthChallenge{}, nil
}

func (q *fakeSQLChallengeQueries) DeleteExpiredAuthChallenges(context.Context, pgtype.Timestamptz) (int64, error) {
	return 0, nil
}

func (q *fakeSQLChallengeQueries) GetAuthChallenge(context.Context, string) (sqlc.AuthChallenge, error) {
	return q.challenge, nil
}

type fakeSQLAuditQueries struct {
	arg sqlc.AppendAuditEventParams
}

func (q *fakeSQLAuditQueries) AppendAuditEvent(_ context.Context, arg sqlc.AppendAuditEventParams) (sqlc.AuditEvent, error) {
	q.arg = arg
	return sqlc.AuditEvent{}, nil
}

func mustAccountID(t testing.TB, value string) account.AccountID {
	t.Helper()
	id, err := account.ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	return id
}

func mustCredentialID(t testing.TB, value string) account.CredentialID {
	t.Helper()
	id, err := account.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("parse credential id: %v", err)
	}
	return id
}
