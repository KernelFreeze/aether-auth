//go:build integration

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/db/sqlc"
	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestSQLStoreRefreshRotationIntegration(t *testing.T) {
	db := testutil.NewPostgresDB(t)
	ctx := context.Background()
	queries := db.Queries
	store := NewSQLStore(db.Pool, queries)
	now := time.Date(2026, 5, 2, 18, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000871")
	sessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000872")
	oldRefreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000873")
	newRefreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000874")
	reuseRefreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000875")
	oldHash := sha256.Sum256(bytes.Repeat([]byte{0x71}, randomTokenBytes))
	newHash := sha256.Sum256(bytes.Repeat([]byte{0x72}, randomTokenBytes))
	reuseHash := sha256.Sum256(bytes.Repeat([]byte{0x73}, randomTokenBytes))

	if _, err := queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		ID:                 accountIDToPG(accountID),
		Username:           "refresh_user",
		UsernameNormalized: "refresh_user",
		DisplayName:        "Refresh User",
		Metadata:           []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.CreateFullSession(ctx, FullSessionRecord{
		Session: SessionRecord{
			ID:        sessionID,
			AccountID: accountID,
			Kind:      sessionKindFull,
			Status:    sessionStatusActive,
			TokenID:   "initial-access-jti",
			ExpiresAt: now.Add(90 * 24 * time.Hour),
		},
		Factors: []FactorRecord{
			{SessionID: sessionID, Kind: account.FactorKindUser, VerifiedAt: now},
			{SessionID: sessionID, Kind: account.FactorKindPassword, VerifiedAt: now},
		},
		RefreshToken: RefreshTokenRecord{
			ID:                oldRefreshID,
			SessionID:         sessionID,
			TokenHash:         oldHash[:],
			Scopes:            []string{"openid", "profile"},
			ExpiresAt:         now.Add(30 * 24 * time.Hour),
			AbsoluteExpiresAt: now.Add(90 * 24 * time.Hour),
		},
	}); err != nil {
		t.Fatalf("create full session: %v", err)
	}

	rotated, err := store.RotateRefreshToken(ctx, RefreshTokenRotation{
		TokenHash:         oldHash[:],
		NewRefreshTokenID: newRefreshID,
		NewTokenHash:      newHash[:],
		RotatedAt:         now.Add(time.Minute),
		RefreshSliding:    time.Hour,
	})
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if rotated.Session.ID != sessionID || rotated.Session.AccountID != accountID {
		t.Fatalf("rotated session = %#v", rotated.Session)
	}
	if rotated.RefreshToken.ParentID != oldRefreshID || rotated.RefreshToken.ExpiresAt != now.Add(time.Minute).Add(time.Hour) {
		t.Fatalf("rotated token = %#v", rotated.RefreshToken)
	}

	oldRow, err := queries.GetRefreshTokenByHash(ctx, oldHash[:])
	if err != nil {
		t.Fatalf("lookup old token: %v", err)
	}
	if !oldRow.RotatedAt.Valid || oldRow.RevokedAt.Valid {
		t.Fatalf("old token state after rotation = %#v", oldRow)
	}
	newRow, err := queries.GetRefreshTokenByHash(ctx, newHash[:])
	if err != nil {
		t.Fatalf("lookup new token: %v", err)
	}
	if uuidFromPG(newRow.ParentID) != oldRefreshID || newRow.RotatedAt.Valid || newRow.RevokedAt.Valid {
		t.Fatalf("new token state after rotation = %#v", newRow)
	}

	_, err = store.RotateRefreshToken(ctx, RefreshTokenRotation{
		TokenHash:         oldHash[:],
		NewRefreshTokenID: reuseRefreshID,
		NewTokenHash:      reuseHash[:],
		RotatedAt:         now.Add(2 * time.Minute),
		RefreshSliding:    time.Hour,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("reuse error = %v, want invalid credentials", err)
	}

	sessionRow, err := queries.GetSessionByID(ctx, sessionIDToPG(sessionID))
	if err != nil {
		t.Fatalf("lookup session: %v", err)
	}
	if sessionRow.Status != sessionStatusRevoked || !sessionRow.RevokedAt.Valid {
		t.Fatalf("session after reuse = %#v", sessionRow)
	}
	oldRow, err = queries.GetRefreshTokenByHash(ctx, oldHash[:])
	if err != nil {
		t.Fatalf("lookup old token after reuse: %v", err)
	}
	newRow, err = queries.GetRefreshTokenByHash(ctx, newHash[:])
	if err != nil {
		t.Fatalf("lookup new token after reuse: %v", err)
	}
	if !oldRow.RevokedAt.Valid || !newRow.RevokedAt.Valid {
		t.Fatalf("refresh family was not revoked: old=%#v new=%#v", oldRow, newRow)
	}
}
