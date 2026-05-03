package totp

import (
	"context"
	"net/netip"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

const defaultMFAEndpoint = "/auth/mfa/verify"

// AttemptFailure describes a failed MFA factor check.
type AttemptFailure struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Factor       account.FactorKind
	IP           netip.Addr
	UserAgent    string
	OccurredAt   time.Time
	Endpoint     string
}

// AttemptSuccess describes a successful MFA factor check.
type AttemptSuccess struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Factor       account.FactorKind
	IP           netip.Addr
	UserAgent    string
	OccurredAt   time.Time
	Endpoint     string
}

// AttemptResult reports the updated lockout state after a failed check.
type AttemptResult struct {
	FailedCount int
	LockedUntil time.Time
}

// AttemptStore records MFA factor success and failure state.
type AttemptStore interface {
	RecordFailure(context.Context, AttemptFailure) (AttemptResult, error)
	RecordSuccess(context.Context, AttemptSuccess) error
}

// LockoutPolicy controls account lockout after repeated MFA failures.
type LockoutPolicy struct {
	MaxFailures     int
	BackoffSchedule []time.Duration
	Endpoint        string
}

func (p LockoutPolicy) endpoint() string {
	if p.Endpoint != "" {
		return p.Endpoint
	}
	return defaultMFAEndpoint
}

func (p LockoutPolicy) maxFailures() int {
	if p.MaxFailures > 0 {
		return p.MaxFailures
	}
	return 5
}

func (p LockoutPolicy) backoffFor(failedCount int) time.Duration {
	if len(p.BackoffSchedule) == 0 {
		return time.Minute
	}
	index := failedCount - p.maxFailures()
	if index < 0 {
		index = 0
	}
	if index >= len(p.BackoffSchedule) {
		index = len(p.BackoffSchedule) - 1
	}
	if p.BackoffSchedule[index] <= 0 {
		return time.Minute
	}
	return p.BackoffSchedule[index]
}
