package account

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
)

func TestSQLCredentialStoreCreateStoresEncryptedPayload(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000311")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000312")
	queries := &fakeCredentialManagementQueries{}
	store := &SQLCredentialStore{queries: queries}

	got, err := store.CreateCredential(ctx, CredentialDraft{
		ID:          credentialID,
		AccountID:   accountID,
		Kind:        CredentialKindPassword,
		DisplayName: "Password",
		Verified:    true,
		Payload: CredentialPayload{
			Algorithm:  credentialPayloadAlgorithm,
			KeyRef:     "env://AUTH_AES_KEY",
			Nonce:      []byte("nonce"),
			Ciphertext: []byte("ciphertext"),
			AAD:        []byte(`{"kind":"password"}`),
			Version:    credentialPayloadVersion,
		},
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if queries.createArg.ID != credentialIDToPG(credentialID) || queries.createArg.DisplayName != "Password" {
		t.Fatalf("create params = %#v", queries.createArg)
	}
	if queries.payloadArg.Algorithm != credentialPayloadAlgorithm || string(queries.payloadArg.Ciphertext) != "ciphertext" {
		t.Fatalf("payload params = %#v", queries.payloadArg)
	}
	if got.ID != credentialID || got.AccountID != accountID || string(got.Payload.Ciphertext) != "ciphertext" {
		t.Fatalf("credential = %#v", got)
	}
}

func TestSQLCredentialStoreRemoveCredentialKeepsLastCredential(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000313")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000314")
	queries := &fakeCredentialManagementQueries{
		listRows: []sqlc.Credential{{ID: credentialIDToPG(credentialID), AccountID: accountIDToPG(accountID)}},
	}
	store := &SQLCredentialStore{queries: queries}

	_, err := store.RemoveCredential(ctx, accountID, credentialID, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrLastCredential) {
		t.Fatalf("remove error = %v, want ErrLastCredential", err)
	}
	if queries.revokeCalled {
		t.Fatal("last credential removal should not call revoke")
	}
}

func TestSQLCredentialStoreRemoveCredentialRevokesWhenAnotherCredentialExists(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000315")
	credentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000316")
	otherCredentialID := mustCredentialCredentialID(t, "018f1f74-10a1-7000-9000-000000000317")
	revokedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	queries := &fakeCredentialManagementQueries{
		listRows: []sqlc.Credential{
			{ID: credentialIDToPG(credentialID), AccountID: accountIDToPG(accountID)},
			{ID: credentialIDToPG(otherCredentialID), AccountID: accountIDToPG(accountID)},
		},
	}
	store := &SQLCredentialStore{queries: queries}

	got, err := store.RemoveCredential(ctx, accountID, credentialID, revokedAt)
	if err != nil {
		t.Fatalf("remove credential: %v", err)
	}
	if !queries.revokeCalled || queries.revokeArg.ID != credentialIDToPG(credentialID) || queries.revokeArg.AccountID != accountIDToPG(accountID) {
		t.Fatalf("revoke params = %#v", queries.revokeArg)
	}
	if got.ID != credentialID || got.RevokedAt.IsZero() {
		t.Fatalf("removed credential = %#v", got)
	}
}

type fakeCredentialManagementQueries struct {
	createArg    sqlc.CreateCredentialParams
	payloadArg   sqlc.UpsertCredentialPayloadParams
	listRows     []sqlc.Credential
	revokeArg    sqlc.RevokeCredentialForAccountParams
	revokeCalled bool
}

func (q *fakeCredentialManagementQueries) CreateCredential(_ context.Context, arg sqlc.CreateCredentialParams) (sqlc.Credential, error) {
	q.createArg = arg
	return sqlc.Credential{
		ID:          arg.ID,
		AccountID:   arg.AccountID,
		Kind:        arg.Kind,
		Provider:    arg.Provider,
		DisplayName: arg.DisplayName,
		Verified:    arg.Verified,
	}, nil
}

func (q *fakeCredentialManagementQueries) GetCredentialByIDForAccount(context.Context, sqlc.GetCredentialByIDForAccountParams) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeCredentialManagementQueries) GetCredentialByProviderSubject(context.Context, sqlc.GetCredentialByProviderSubjectParams) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeCredentialManagementQueries) GetCredentialPayload(context.Context, pgtype.UUID) (sqlc.CredentialPayload, error) {
	if len(q.payloadArg.Ciphertext) == 0 {
		return sqlc.CredentialPayload{}, pgx.ErrNoRows
	}
	return sqlc.CredentialPayload{
		Algorithm:  q.payloadArg.Algorithm,
		KeyRef:     q.payloadArg.KeyRef,
		Nonce:      q.payloadArg.Nonce,
		Ciphertext: q.payloadArg.Ciphertext,
		Aad:        q.payloadArg.Aad,
		Version:    q.payloadArg.Version,
	}, nil
}

func (q *fakeCredentialManagementQueries) ListCredentialsByAccount(context.Context, pgtype.UUID) ([]sqlc.Credential, error) {
	return q.listRows, nil
}

func (q *fakeCredentialManagementQueries) RevokeCredentialForAccount(_ context.Context, arg sqlc.RevokeCredentialForAccountParams) (sqlc.Credential, error) {
	q.revokeCalled = true
	q.revokeArg = arg
	return sqlc.Credential{
		ID:        arg.ID,
		AccountID: arg.AccountID,
		RevokedAt: arg.RevokedAt,
	}, nil
}

func (q *fakeCredentialManagementQueries) UpdateCredentialStateForAccount(context.Context, sqlc.UpdateCredentialStateForAccountParams) (sqlc.Credential, error) {
	return sqlc.Credential{}, pgx.ErrNoRows
}

func (q *fakeCredentialManagementQueries) UpsertCredentialPayload(_ context.Context, arg sqlc.UpsertCredentialPayloadParams) (sqlc.CredentialPayload, error) {
	q.payloadArg = arg
	return sqlc.CredentialPayload{
		Algorithm:  arg.Algorithm,
		KeyRef:     arg.KeyRef,
		Nonce:      arg.Nonce,
		Ciphertext: arg.Ciphertext,
		Aad:        arg.Aad,
		Version:    arg.Version,
	}, nil
}
