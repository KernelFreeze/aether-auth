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
		NewAccessTokenID:  "rotated-access-jti",
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
	if rotated.Session.TokenID != "rotated-access-jti" {
		t.Fatalf("rotated session token id = %q, want rotated-access-jti", rotated.Session.TokenID)
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
		NewAccessTokenID:  "reuse-access-jti",
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

func TestSQLStoreSessionRevocationIntegration(t *testing.T) {
	db := testutil.NewPostgresDB(t)
	ctx := context.Background()
	queries := db.Queries
	store := NewSQLStore(db.Pool, queries)
	now := time.Date(2026, 5, 2, 20, 0, 0, 0, time.UTC)
	accountID := mustAccountID(t, "018f1f74-10a1-7000-9000-000000000971")
	firstSessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000972")
	secondSessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000973")
	partialSessionID := mustSessionID(t, "018f1f74-10a1-7000-9000-000000000976")
	firstRefreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000974")
	secondRefreshID := uuid.MustParse("018f1f74-10a1-7000-9000-000000000975")
	firstHash := sha256.Sum256(bytes.Repeat([]byte{0x81}, randomTokenBytes))
	secondHash := sha256.Sum256(bytes.Repeat([]byte{0x82}, randomTokenBytes))

	if _, err := queries.CreateAccount(ctx, sqlc.CreateAccountParams{
		ID:                 accountIDToPG(accountID),
		Username:           "revocation_user",
		UsernameNormalized: "revocation_user",
		DisplayName:        "Revocation User",
		Metadata:           []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	for _, seed := range []struct {
		sessionID account.SessionID
		refreshID uuid.UUID
		tokenID   string
		hash      []byte
	}{
		{sessionID: firstSessionID, refreshID: firstRefreshID, tokenID: "first-access-jti", hash: firstHash[:]},
		{sessionID: secondSessionID, refreshID: secondRefreshID, tokenID: "second-access-jti", hash: secondHash[:]},
	} {
		fingerprintID := "revocation-user-agent-" + seed.tokenID
		if err := store.CreateFullSession(ctx, FullSessionRecord{
			Session: SessionRecord{
				ID:          seed.sessionID,
				AccountID:   accountID,
				Kind:        sessionKindFull,
				Status:      sessionStatusActive,
				TokenID:     seed.tokenID,
				UserAgentID: fingerprintID,
				IP:          "203.0.113.10",
				ExpiresAt:   now.Add(90 * 24 * time.Hour),
			},
			UserAgent: UserAgentRecord{
				FingerprintID: fingerprintID,
				IP:            "203.0.113.10",
				Description:   "Revocation Test Browser",
				Headers:       []byte(`{}`),
			},
			RefreshToken: RefreshTokenRecord{
				ID:                seed.refreshID,
				SessionID:         seed.sessionID,
				TokenHash:         seed.hash,
				Scopes:            []string{"openid", "profile"},
				ExpiresAt:         now.Add(30 * 24 * time.Hour),
				AbsoluteExpiresAt: now.Add(90 * 24 * time.Hour),
			},
		}); err != nil {
			t.Fatalf("create seeded session: %v", err)
		}
	}
	if err := store.CreatePartialSession(ctx, PartialSessionRecord{
		Session: SessionRecord{
			ID:        partialSessionID,
			AccountID: accountID,
			Kind:      sessionKindPartial,
			Status:    sessionStatusActive,
			ExpiresAt: now.Add(time.Minute),
		},
	}); err != nil {
		t.Fatalf("create partial session: %v", err)
	}

	active, err := store.ListActiveSessions(ctx, accountID, now)
	if err != nil {
		t.Fatalf("list active sessions: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("active full sessions length = %d, want 2: %#v", len(active), active)
	}
	if active[0].UserAgent != "Revocation Test Browser" || active[0].IP != "203.0.113.10" {
		t.Fatalf("active session device view = %#v", active[0])
	}

	revoked, err := store.RevokeSession(ctx, SessionRevocation{
		SessionID: firstSessionID,
		AccountID: accountID,
		RevokedAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("revoke one session: %v", err)
	}
	if revoked.ID != firstSessionID || revoked.TokenID != "first-access-jti" {
		t.Fatalf("revoked session = %#v", revoked)
	}
	firstRow, err := queries.GetSessionByID(ctx, sessionIDToPG(firstSessionID))
	if err != nil {
		t.Fatalf("lookup first session: %v", err)
	}
	if firstRow.Status != sessionStatusRevoked || !firstRow.RevokedAt.Valid {
		t.Fatalf("first session not revoked: %#v", firstRow)
	}
	firstRefresh, err := queries.GetRefreshTokenByHash(ctx, firstHash[:])
	if err != nil {
		t.Fatalf("lookup first refresh: %v", err)
	}
	if !firstRefresh.RevokedAt.Valid {
		t.Fatalf("first refresh token not revoked: %#v", firstRefresh)
	}

	revokedRows, err := store.RevokeAccountSessions(ctx, AccountSessionsRevocation{
		AccountID: accountID,
		RevokedAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("revoke account sessions: %v", err)
	}
	if len(revokedRows) != 1 || revokedRows[0].ID != secondSessionID {
		t.Fatalf("account revoked sessions = %#v", revokedRows)
	}
	secondRefresh, err := queries.GetRefreshTokenByHash(ctx, secondHash[:])
	if err != nil {
		t.Fatalf("lookup second refresh: %v", err)
	}
	if !secondRefresh.RevokedAt.Valid {
		t.Fatalf("second refresh token not revoked: %#v", secondRefresh)
	}
}
