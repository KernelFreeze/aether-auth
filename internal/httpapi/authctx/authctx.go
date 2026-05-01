// Package authctx stores authenticated account facts on Gin contexts.
package authctx

import (
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// AccountIDKey stores the authenticated account ID as a canonical UUID
	// string. Feature handlers parse it into their local ID type.
	AccountIDKey = "aether.auth.account_id"
	// ReauthenticatedAtKey stores the last primary-authentication time used
	// for destructive account settings actions.
	ReauthenticatedAtKey = "aether.auth.reauthenticated_at"
)

// SetAccountID records the authenticated account ID for downstream handlers.
func SetAccountID(c *gin.Context, accountID string) {
	c.Set(AccountIDKey, accountID)
}

// AccountID returns the authenticated account ID string from c.
func AccountID(c *gin.Context) (string, bool) {
	value, exists := c.Get(AccountIDKey)
	if !exists {
		return "", false
	}
	accountID, ok := value.(string)
	return accountID, ok && accountID != ""
}

// SetReauthenticatedAt records the caller's most recent primary-auth time.
func SetReauthenticatedAt(c *gin.Context, at time.Time) {
	c.Set(ReauthenticatedAtKey, at)
}

// ReauthenticatedAt returns the caller's most recent primary-auth time.
func ReauthenticatedAt(c *gin.Context) (time.Time, bool) {
	value, exists := c.Get(ReauthenticatedAtKey)
	if !exists {
		return time.Time{}, false
	}
	at, ok := value.(time.Time)
	return at, ok && !at.IsZero()
}
