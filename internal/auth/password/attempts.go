package password

import (
	"context"
	"net/netip"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
)

const defaultLoginEndpoint = "/auth/login"

// AttemptFailure describes a failed password verification.
type AttemptFailure struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Username     string
	IP           netip.Addr
	OccurredAt   time.Time
	Endpoint     string
}

// AttemptSuccess describes a successful password verification.
type AttemptSuccess struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Username     string
	IP           netip.Addr
	OccurredAt   time.Time
	Endpoint     string
}

// AttemptResult reports the updated lockout state after a failure.
type AttemptResult struct {
	FailedCount int
	LockedUntil time.Time
}

// AttemptStore records password login success and failure state.
type AttemptStore interface {
	RecordFailure(context.Context, AttemptFailure) (AttemptResult, error)
	RecordSuccess(context.Context, AttemptSuccess) error
}

// LockoutPolicy controls account lockout after failed password verification.
type LockoutPolicy struct {
	MaxFailures     int
	BackoffSchedule []time.Duration
	Endpoint        string
}

func (p LockoutPolicy) endpoint() string {
	if p.Endpoint != "" {
		return p.Endpoint
	}
	return defaultLoginEndpoint
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
