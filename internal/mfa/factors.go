package mfa

import (
	"fmt"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

// SessionFactor records the latest state for one factor in an in-progress or
// issued login session. The shape is adapted from Zitadel's session factor
// model, but Aether keeps one compact record keyed by account.FactorKind.
type SessionFactor struct {
	Kind             account.FactorKind
	AccountID        account.AccountID
	ChallengeBinding string
	LastVerifiedAt   time.Time
	LastFailedAt     time.Time
	UserVerified     bool
}

// FactorUpdate describes one successful or failed factor check.
type FactorUpdate struct {
	Kind             account.FactorKind
	AccountID        account.AccountID
	ChallengeBinding string
	CheckedAt        time.Time
	UserVerified     bool
}

// SessionFactors is the factor state attached to a partial or full session.
type SessionFactors []SessionFactor

// Verified reports whether the factor's latest check succeeded.
func (f SessionFactor) Verified() bool {
	verifiedAt := account.NormalizeTimestamp(f.LastVerifiedAt)
	if !f.Kind.Valid() || verifiedAt.IsZero() {
		return false
	}
	failedAt := account.NormalizeTimestamp(f.LastFailedAt)
	return failedAt.IsZero() || !verifiedAt.Before(failedAt)
}

// Failed reports whether the factor's latest check failed.
func (f SessionFactor) Failed() bool {
	failedAt := account.NormalizeTimestamp(f.LastFailedAt)
	if !f.Kind.Valid() || failedAt.IsZero() {
		return false
	}
	verifiedAt := account.NormalizeTimestamp(f.LastVerifiedAt)
	return verifiedAt.IsZero() || failedAt.After(verifiedAt)
}

// Get returns the factor for kind.
func (factors SessionFactors) Get(kind account.FactorKind) (SessionFactor, bool) {
	for _, factor := range factors {
		if factor.Kind == kind {
			return factor, true
		}
	}
	return SessionFactor{}, false
}

// GetUserFactor returns the user factor.
func (factors SessionFactors) GetUserFactor() (SessionFactor, bool) {
	return factors.Get(account.FactorKindUser)
}

// GetPasswordFactor returns the password factor.
func (factors SessionFactors) GetPasswordFactor() (SessionFactor, bool) {
	return factors.Get(account.FactorKindPassword)
}

// GetIDPFactor returns the external identity-provider factor.
func (factors SessionFactors) GetIDPFactor() (SessionFactor, bool) {
	return factors.Get(account.FactorKindIDP)
}

// GetPasskeyFactor returns the passkey factor.
func (factors SessionFactors) GetPasskeyFactor() (SessionFactor, bool) {
	return factors.Get(account.FactorKindPasskey)
}

// GetTOTPFactor returns the TOTP factor.
func (factors SessionFactors) GetTOTPFactor() (SessionFactor, bool) {
	return factors.Get(account.FactorKindTOTP)
}

// GetRecoveryCodeFactor returns the recovery-code factor.
func (factors SessionFactors) GetRecoveryCodeFactor() (SessionFactor, bool) {
	return factors.Get(account.FactorKindRecoveryCode)
}

// VerifiedKinds returns each successfully verified factor kind in session order.
func (factors SessionFactors) VerifiedKinds() []account.FactorKind {
	kinds := make([]account.FactorKind, 0, len(factors))
	for _, factor := range factors {
		if factor.Verified() {
			kinds = append(kinds, factor.Kind)
		}
	}
	return NormalizeFactorKinds(kinds)
}

// MarkVerified returns a copy with update recorded as the latest successful
// check for its factor kind.
func (factors SessionFactors) MarkVerified(update FactorUpdate) (SessionFactors, error) {
	factor, err := verifiedFactor(update)
	if err != nil {
		return nil, err
	}
	return factors.upsert(factor), nil
}

// MarkFailed returns a copy with update recorded as the latest failed check for
// its factor kind.
func (factors SessionFactors) MarkFailed(update FactorUpdate) (SessionFactors, error) {
	factor, err := failedFactor(update)
	if err != nil {
		return nil, err
	}
	return factors.upsert(factor), nil
}

// MarkUserVerified records account identity selection.
func (factors SessionFactors) MarkUserVerified(accountID account.AccountID, checkedAt time.Time) (SessionFactors, error) {
	return factors.MarkVerified(FactorUpdate{
		Kind:      account.FactorKindUser,
		AccountID: accountID,
		CheckedAt: checkedAt,
	})
}

// MarkPasswordVerified records successful password verification.
func (factors SessionFactors) MarkPasswordVerified(checkedAt time.Time, binding string) (SessionFactors, error) {
	return factors.MarkVerified(FactorUpdate{
		Kind:             account.FactorKindPassword,
		ChallengeBinding: binding,
		CheckedAt:        checkedAt,
	})
}

// MarkPasswordFailed records a failed password check.
func (factors SessionFactors) MarkPasswordFailed(checkedAt time.Time, binding string) (SessionFactors, error) {
	return factors.MarkFailed(FactorUpdate{
		Kind:             account.FactorKindPassword,
		ChallengeBinding: binding,
		CheckedAt:        checkedAt,
	})
}

// MarkTOTPVerified records successful TOTP verification.
func (factors SessionFactors) MarkTOTPVerified(checkedAt time.Time, binding string) (SessionFactors, error) {
	return factors.MarkVerified(FactorUpdate{
		Kind:             account.FactorKindTOTP,
		ChallengeBinding: binding,
		CheckedAt:        checkedAt,
	})
}

// MarkTOTPFailed records a failed TOTP check.
func (factors SessionFactors) MarkTOTPFailed(checkedAt time.Time, binding string) (SessionFactors, error) {
	return factors.MarkFailed(FactorUpdate{
		Kind:             account.FactorKindTOTP,
		ChallengeBinding: binding,
		CheckedAt:        checkedAt,
	})
}

// MarkRecoveryCodeVerified records successful recovery-code verification.
func (factors SessionFactors) MarkRecoveryCodeVerified(checkedAt time.Time, binding string) (SessionFactors, error) {
	return factors.MarkVerified(FactorUpdate{
		Kind:             account.FactorKindRecoveryCode,
		ChallengeBinding: binding,
		CheckedAt:        checkedAt,
	})
}

// MarkRecoveryCodeFailed records a failed recovery-code check.
func (factors SessionFactors) MarkRecoveryCodeFailed(checkedAt time.Time, binding string) (SessionFactors, error) {
	return factors.MarkFailed(FactorUpdate{
		Kind:             account.FactorKindRecoveryCode,
		ChallengeBinding: binding,
		CheckedAt:        checkedAt,
	})
}

// NormalizeFactorKinds removes invalid and duplicate factor kinds while
// preserving the first valid occurrence.
func NormalizeFactorKinds(values []account.FactorKind) []account.FactorKind {
	seen := make(map[account.FactorKind]struct{}, len(values))
	normalized := make([]account.FactorKind, 0, len(values))
	for _, factor := range values {
		if !factor.Valid() {
			continue
		}
		if _, ok := seen[factor]; ok {
			continue
		}
		seen[factor] = struct{}{}
		normalized = append(normalized, factor)
	}
	return normalized
}

func (factors SessionFactors) upsert(next SessionFactor) SessionFactors {
	cloned := append(SessionFactors(nil), factors...)
	for i, factor := range cloned {
		if factor.Kind == next.Kind {
			cloned[i] = next
			return cloned
		}
	}
	return append(cloned, next)
}

func verifiedFactor(update FactorUpdate) (SessionFactor, error) {
	if err := validateFactorUpdate(update); err != nil {
		return SessionFactor{}, err
	}
	return SessionFactor{
		Kind:             update.Kind,
		AccountID:        update.AccountID,
		ChallengeBinding: update.ChallengeBinding,
		LastVerifiedAt:   account.NormalizeTimestamp(update.CheckedAt),
		UserVerified:     update.UserVerified,
	}, nil
}

func failedFactor(update FactorUpdate) (SessionFactor, error) {
	if err := validateFactorUpdate(update); err != nil {
		return SessionFactor{}, err
	}
	return SessionFactor{
		Kind:             update.Kind,
		AccountID:        update.AccountID,
		ChallengeBinding: update.ChallengeBinding,
		LastFailedAt:     account.NormalizeTimestamp(update.CheckedAt),
		UserVerified:     update.UserVerified,
	}, nil
}

func validateFactorUpdate(update FactorUpdate) error {
	if !update.Kind.Valid() {
		return fmt.Errorf("mfa: invalid factor kind %q", update.Kind)
	}
	if account.NormalizeTimestamp(update.CheckedAt).IsZero() {
		return fmt.Errorf("mfa: factor check time is required")
	}
	return nil
}
