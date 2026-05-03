//go:build integration

package totp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestSQLRecoveryCodeStoreIntegration(t *testing.T) {
	db := testutil.NewPostgresDB(t)
	ctx := context.Background()
	queries := db.Queries
	store := NewSQLRecoveryCodeStore(db.Pool)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000002201")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000002202")
	now := time.Date(2026, 5, 3, 14, 0, 0, 0, time.UTC)

	seedRecoveryAccount(t, ctx, queries, accountID, credentialID)

	records, err := store.ReplaceRecoveryCodes(ctx, RecoveryCodeSet{
		AccountID:    accountID,
		CredentialID: credentialID,
		CodeHashes:   [][]byte{[]byte("hash-one"), []byte("hash-two")},
	})
	if err != nil {
		t.Fatalf("replace recovery codes: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}

	unused, err := store.ListUnusedRecoveryCodes(ctx, accountID, credentialID)
	if err != nil {
		t.Fatalf("list unused recovery codes: %v", err)
	}
	if len(unused) != 2 || string(unused[0].CodeHash) != "hash-one" {
		t.Fatalf("unused recovery codes = %#v", unused)
	}

	consumed, err := store.ConsumeRecoveryCode(ctx, RecoveryCodeConsumption{
		ID:           unused[0].ID,
		AccountID:    accountID,
		CredentialID: credentialID,
		UsedAt:       now,
	})
	if err != nil {
		t.Fatalf("consume recovery code: %v", err)
	}
	if consumed.UsedAt != now {
		t.Fatalf("used_at = %v, want %v", consumed.UsedAt, now)
	}
	if _, err := store.ConsumeRecoveryCode(ctx, RecoveryCodeConsumption{
		ID:           unused[0].ID,
		AccountID:    accountID,
		CredentialID: credentialID,
		UsedAt:       now.Add(time.Second),
	}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("replay consume error = %v, want invalid credentials", err)
	}

	unused, err = store.ListUnusedRecoveryCodes(ctx, accountID, credentialID)
	if err != nil {
		t.Fatalf("list after consume: %v", err)
	}
	if len(unused) != 1 || string(unused[0].CodeHash) != "hash-two" {
		t.Fatalf("unused after consume = %#v", unused)
	}
}

func TestSQLAttemptStoreIntegration(t *testing.T) {
	db := testutil.NewPostgresDB(t)
	ctx := context.Background()
	queries := db.Queries
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000002203")
	credentialID := mustCredentialID(t, "018f1f74-10a1-7000-9000-000000002204")
	now := time.Date(2026, 5, 3, 14, 0, 0, 0, time.UTC)
	seedRecoveryAccount(t, ctx, queries, accountID, credentialID)

	store := NewSQLAttemptStore(db.Pool, LockoutPolicy{
		MaxFailures:     2,
		BackoffSchedule: []time.Duration{time.Minute},
	})
	first, err := store.RecordFailure(ctx, AttemptFailure{
		AccountID:    accountID,
		CredentialID: credentialID,
		Factor:       account.FactorKindTOTP,
		OccurredAt:   now,
	})
	if err != nil {
		t.Fatalf("record first failure: %v", err)
	}
	if first.FailedCount != 1 || !first.LockedUntil.IsZero() {
		t.Fatalf("first failure result = %#v", first)
	}

	second, err := store.RecordFailure(ctx, AttemptFailure{
		AccountID:    accountID,
		CredentialID: credentialID,
		Factor:       account.FactorKindTOTP,
		OccurredAt:   now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("record second failure: %v", err)
	}
	if second.FailedCount != 2 || second.LockedUntil.IsZero() {
		t.Fatalf("second failure result = %#v", second)
	}
	row, err := queries.GetAccountByID(ctx, accountIDToPG(accountID))
	if err != nil {
		t.Fatalf("lookup locked account: %v", err)
	}
	if !row.LockedUntil.Valid {
		t.Fatalf("account lockout was not set: %#v", row)
	}

	if err := store.RecordSuccess(ctx, AttemptSuccess{
		AccountID:    accountID,
		CredentialID: credentialID,
		Factor:       account.FactorKindTOTP,
		OccurredAt:   now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("record success: %v", err)
	}
	row, err = queries.GetAccountByID(ctx, accountIDToPG(accountID))
	if err != nil {
		t.Fatalf("lookup cleared account: %v", err)
	}
	if row.LockedUntil.Valid {
		t.Fatalf("account lockout was not cleared: %#v", row)
	}
}

func seedRecoveryAccount(t testing.TB, ctx context.Context, queries *sqlc.Queries, accountID account.AccountID, credentialID account.CredentialID) {
	t.Helper()
	if _, err := queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		ID:                 accountIDToPG(accountID),
		Username:           "mfa_user_" + accountID.String()[len(accountID.String())-4:],
		UsernameNormalized: "mfa_user_" + accountID.String()[len(accountID.String())-4:],
		DisplayName:        "MFA User",
		Metadata:           []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := queries.CreateCredential(ctx, sqlc.CreateCredentialParams{
		ID:        credentialIDToPG(credentialID),
		AccountID: accountIDToPG(accountID),
		Kind:      account.CredentialKindRecoveryCode.String(),
		Verified:  true,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if _, err := queries.GetCredentialByID(ctx, credentialIDToPG(credentialID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("seeded recovery-code credential is missing")
		}
		t.Fatalf("lookup seeded credential: %v", err)
	}
}
