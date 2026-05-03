package totp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

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

func normalizeAttemptTime(t time.Time) time.Time {
	if t.IsZero() {
		t = time.Now()
	}
	return account.NormalizeTimestamp(t)
}

func attemptEndpoint(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func attemptSubjectHash(accountID account.AccountID, factor account.FactorKind) string {
	sum := sha256.Sum256([]byte(accountID.String() + ":" + factor.String()))
	return hex.EncodeToString(sum[:])
}

func optionalAttemptAddr(ip netip.Addr) *netip.Addr {
	if !ip.IsValid() {
		return nil
	}
	return &ip
}
