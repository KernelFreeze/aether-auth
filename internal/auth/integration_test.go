//go:build integration

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestSQLRepositoriesIntegration(t *testing.T) {
	db := testutil.NewPostgresDB(t)
	ctx := context.Background()
	queries := db.Queries

	t.Run("migrations create repository tables", func(t *testing.T) {
		for _, table := range []string{"accounts", "credentials", "auth_challenges", "audit_events"} {
			assertTableExists(t, ctx, db.Pool, table)
		}

		var dirty bool
		if err := db.Pool.QueryRow(ctx, `SELECT dirty FROM schema_migrations`).Scan(&dirty); err != nil {
			t.Fatalf("read schema migration state: %v", err)
		}
		if dirty {
			t.Fatal("schema migration state is dirty")
		}
	})

	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000101")
	emailID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000102")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000000103")
	secondCredentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000000104")
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	if _, err := queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		ID:                 accountIDToPG(accountID),
		Username:           "Celeste",
		UsernameNormalized: "celeste",
		DisplayName:        "Celeste",
		MfaRequired:        true,
		Metadata:           []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := queries.CreateEmail(ctx, sqlc.CreateEmailParams{
		ID:                accountIDToPG(emailID),
		AccountID:         accountIDToPG(accountID),
		Address:           "Celeste@example.com",
		AddressNormalized: "celeste@example.com",
		Verified:          true,
		IsPrimary:         true,
		VerifiedAt:        timeToTimestamptz(now),
	}); err != nil {
		t.Fatalf("seed email: %v", err)
	}

	t.Run("account lookup normalizes public identifiers", func(t *testing.T) {
		repo := NewSQLAccountRepository(queries)

		byUsername, err := repo.LookupAccount(ctx, AccountLookup{Username: "  CELESTE  "})
		if err != nil {
			t.Fatalf("lookup account by username: %v", err)
		}
		if byUsername.ID != accountID || byUsername.Username != "Celeste" || !byUsername.MFARequired {
			t.Fatalf("account by username = %#v", byUsername)
		}

		byEmail, err := repo.LookupAccount(ctx, AccountLookup{Email: "  CELESTE@EXAMPLE.COM  "})
		if err != nil {
			t.Fatalf("lookup account by email: %v", err)
		}
		if byEmail.ID != accountID {
			t.Fatalf("email lookup account id = %s, want %s", byEmail.ID, accountID)
		}
	})

	credentialRepo := NewSQLCredentialRepository(
		queries,
		fakeIDGenerator{credentialID: credentialID},
		CredentialPayloadConfig{
			Algorithm: "aes-256-gcm",
			KeyRef:    "env://AUTH_CREDENTIAL_KEY",
			Nonce:     []byte("nonce-123"),
			AAD:       []byte(`{"purpose":"password"}`),
			Version:   1,
		},
	)

	t.Run("credential repository stores payloads and last credential rules", func(t *testing.T) {
		created, err := credentialRepo.CreateCredential(ctx, CredentialDraft{
			AccountID:        accountID,
			Kind:             account.CredentialKindPassword,
			EncryptedPayload: []byte("ciphertext"),
			Verified:         true,
		})
		if err != nil {
			t.Fatalf("create credential: %v", err)
		}
		if created.ID != credentialID || string(created.EncryptedPayload) != "ciphertext" {
			t.Fatalf("created credential = %#v", created)
		}

		lookup, err := credentialRepo.LookupCredential(ctx, CredentialLookup{
			AccountID: accountID,
			Kind:      account.CredentialKindPassword,
		})
		if err != nil {
			t.Fatalf("lookup credential: %v", err)
		}
		if lookup.ID != credentialID || !lookup.Verified || string(lookup.EncryptedPayload) != "ciphertext" {
			t.Fatalf("credential lookup = %#v", lookup)
		}

		canRemove, err := credentialRepo.CanRemoveCredential(ctx, accountID, credentialID)
		if err != nil {
			t.Fatalf("check last credential: %v", err)
		}
		if canRemove {
			t.Fatal("single active credential should not be removable")
		}

		if _, err := queries.CreateCredential(ctx, sqlc.CreateCredentialParams{
			ID:        credentialIDToPG(secondCredentialID),
			AccountID: accountIDToPG(accountID),
			Kind:      account.CredentialKindWebAuthn.String(),
			Verified:  true,
		}); err != nil {
			t.Fatalf("seed second credential: %v", err)
		}

		canRemove, err = credentialRepo.CanRemoveCredential(ctx, accountID, credentialID)
		if err != nil {
			t.Fatalf("check removable credential: %v", err)
		}
		if !canRemove {
			t.Fatal("credential should be removable when another active credential exists")
		}
	})

	t.Run("challenge store consumes once and deletes expired rows", func(t *testing.T) {
		store := NewSQLChallengeStore(queries, fakeClock{now: now})
		if err := store.SaveChallenge(ctx, StoredChallenge{
			ID:             "chal_live",
			Purpose:        ChallengePurposeWebAuthn,
			AccountID:      accountID,
			CredentialID:   credentialID,
			SessionBinding: "binding",
			RequestID:      "req_live",
			Payload:        []byte(`{"challenge":"live"}`),
			ExpiresAt:      now.Add(time.Minute),
		}); err != nil {
			t.Fatalf("save challenge: %v", err)
		}

		consumed, err := store.ConsumeChallenge(ctx, ChallengeLookup{
			ID:             "chal_live",
			Purpose:        ChallengePurposeWebAuthn,
			SessionBinding: "binding",
		})
		if err != nil {
			t.Fatalf("consume challenge: %v", err)
		}
		if consumed.ID != "chal_live" || string(consumed.Payload) != `{"challenge":"live"}` {
			t.Fatalf("consumed challenge = %#v", consumed)
		}

		_, err = store.ConsumeChallenge(ctx, ChallengeLookup{
			ID:             "chal_live",
			Purpose:        ChallengePurposeWebAuthn,
			SessionBinding: "binding",
		})
		if !errors.Is(err, ErrReplayedChallenge) {
			t.Fatalf("replay error = %v, want %v", err, ErrReplayedChallenge)
		}

		if err := store.SaveChallenge(ctx, StoredChallenge{
			ID:             "chal_expired",
			Purpose:        ChallengePurposeWebAuthn,
			SessionBinding: "binding",
			RequestID:      "req_expired",
			Payload:        []byte(`{}`),
			ExpiresAt:      now.Add(-time.Second),
		}); err != nil {
			t.Fatalf("save expired challenge: %v", err)
		}
		if err := store.DeleteExpiredChallenges(ctx, now); err != nil {
			t.Fatalf("delete expired challenges: %v", err)
		}
		if _, err := queries.GetAuthChallenge(ctx, "chal_expired"); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expired challenge lookup error = %v, want no rows", err)
		}
	})

	t.Run("audit writer appends queryable security events", func(t *testing.T) {
		writer := NewSQLAuditWriter(queries)
		err := writer.WriteAuditEvent(ctx, AuditEvent{
			Type:         "auth.login.succeeded",
			AccountID:    accountID,
			CredentialID: credentialID,
			RequestID:    "req_audit",
			IP:           "2001:db8::1",
			UserAgent:    "integration-test",
			OccurredAt:   now,
			Attributes:   map[string]string{"method": "password"},
		})
		if err != nil {
			t.Fatalf("write audit event: %v", err)
		}

		events, err := queries.ListRecentLoginAuditEvents(ctx, sqlc.ListRecentLoginAuditEventsParams{
			AccountID:  accountIDToPG(accountID),
			EventTypes: []string{"auth.login.succeeded"},
			RowLimit:   1,
		})
		if err != nil {
			t.Fatalf("list audit events: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("audit event count = %d, want 1", len(events))
		}
		if events[0].Ip == nil || *events[0].Ip != netip.MustParseAddr("2001:db8::1") {
			t.Fatalf("audit event ip = %v", events[0].Ip)
		}
		var attributes map[string]string
		if err := json.Unmarshal(events[0].Attributes, &attributes); err != nil {
			t.Fatalf("decode audit attributes: %v", err)
		}
		if attributes["method"] != "password" {
			t.Fatalf("audit attributes = %#v", attributes)
		}
	})
}

func assertTableExists(t testing.TB, ctx context.Context, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, table string) {
	t.Helper()

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil {
		t.Fatalf("lookup table %s: %v", table, err)
	}
	if !exists {
		t.Fatalf("table %s is missing", table)
	}
}
