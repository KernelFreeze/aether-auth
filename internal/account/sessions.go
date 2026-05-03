package account

import (
	"errors"
	"time"
)

var (
	// ErrInvalidSession means an account session request is malformed.
	ErrInvalidSession = errors.New("account: invalid session")
	// ErrSessionNotFound means no active session matched the authenticated account.
	ErrSessionNotFound = errors.New("account: session not found")
)

// AccountSession is the public self-service view of one active login session.
// It intentionally omits access-token IDs, refresh-token IDs, and token hashes.
type AccountSession struct {
	ID        SessionID
	AccountID AccountID
	ClientID  ClientID
	IP        string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
}
