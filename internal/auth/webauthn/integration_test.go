//go:build integration

package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestSQLCredentialStoreIntegration(t *testing.T) {
	db := testutil.NewPostgresDB(t)
	ctx := context.Background()
	store := NewSQLCredentialStore(db.Pool)
	accountID := mustWebAuthnAccountID(t, "018f1f74-10a1-7000-9000-000000008101")
	credentialID := mustWebAuthnCredentialID(t, "018f1f74-10a1-7000-9000-000000008102")
	now := time.Date(2026, 5, 3, 16, 0, 0, 0, time.UTC)

	seedWebAuthnAccount(t, ctx, db.Queries, accountID)

	created, err := store.CreateCredential(ctx, Credential{
		ID:                      credentialID,
		AccountID:               accountID,
		KeyID:                   []byte("key-id"),
		PublicKey:               []byte("public-key"),
		AttestationType:         "none",
		Transports:              []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal},
		AAGUID:                  []byte("aaguid"),
		SignCount:               4,
		RelyingPartyID:          "localhost",
		UserVerified:            true,
		BackupEligible:          true,
		BackedUp:                true,
		AuthenticatorAttachment: AuthenticatorAttachmentPlatform,
		DisplayName:             "laptop passkey",
		Verified:                true,
	})
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if created.ID != credentialID || created.AccountID != accountID || created.DisplayName != "laptop passkey" {
		t.Fatalf("created credential = %#v", created)
	}
	if !bytes.Equal(created.KeyID, []byte("key-id")) || !bytes.Equal(created.PublicKey, []byte("public-key")) {
		t.Fatalf("created credential key material = %#v", created)
	}
	if !created.BackupEligible || !created.BackedUp || created.AuthenticatorAttachment != AuthenticatorAttachmentPlatform {
		t.Fatalf("created credential backup metadata = %#v", created)
	}
	if len(created.Transports) != 2 || created.Transports[0] != protocol.USB || created.Transports[1] != protocol.Internal {
		t.Fatalf("created credential transports = %#v", created.Transports)
	}

	listed, err := store.ListCredentials(ctx, accountID, "localhost")
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != credentialID {
		t.Fatalf("listed credentials = %#v", listed)
	}
	none, err := store.ListCredentials(ctx, accountID, "example.com")
	if err != nil {
		t.Fatalf("list credentials for other rp: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("other relying party credentials = %#v", none)
	}

	created.SignCount = 9
	created.UserVerified = false
	created.BackupEligible = false
	created.BackedUp = false
	created.LastUsedAt = now
	created.Transports = []protocol.AuthenticatorTransport{protocol.NFC}
	updated, err := store.UpdateCredentialAssertion(ctx, created)
	if err != nil {
		t.Fatalf("update assertion: %v", err)
	}
	if updated.SignCount != 9 || updated.UserVerified || updated.BackupEligible || updated.BackedUp {
		t.Fatalf("updated credential = %#v", updated)
	}
	if updated.LastUsedAt != now || len(updated.Transports) != 1 || updated.Transports[0] != protocol.NFC {
		t.Fatalf("updated assertion metadata = %#v", updated)
	}

	byKeyID, err := store.GetCredentialByKeyID(ctx, []byte("key-id"))
	if err != nil {
		t.Fatalf("get by key id: %v", err)
	}
	if byKeyID.ID != credentialID || byKeyID.SignCount != 9 {
		t.Fatalf("by key id = %#v", byKeyID)
	}

	if _, err := store.GetCredentialByKeyID(ctx, []byte("missing")); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("missing key id error = %v, want invalid credentials", err)
	}
}

func seedWebAuthnAccount(t testing.TB, ctx context.Context, queries *sqlc.Queries, accountID account.AccountID) {
	t.Helper()
	if _, err := queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		ID:                 accountIDToPG(accountID),
		Username:           "passkey_user_" + accountID.String()[len(accountID.String())-4:],
		UsernameNormalized: "passkey_user_" + accountID.String()[len(accountID.String())-4:],
		DisplayName:        "Passkey User",
		Metadata:           []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

func mustWebAuthnCredentialID(t testing.TB, value string) account.CredentialID {
	t.Helper()
	id, err := account.ParseCredentialID(value)
	if err != nil {
		t.Fatalf("parse credential id: %v", err)
	}
	return id
}
