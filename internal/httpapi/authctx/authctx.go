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
	// SessionIDKey stores the authenticated full session ID as a canonical
	// UUID string.
	SessionIDKey = "aether.auth.session_id"
	// AccessTokenIDKey stores the authenticated access token jti.
	AccessTokenIDKey = "aether.auth.access_token_id"
	// ScopesKey stores the space-delimited access-token scopes as a string
	// slice.
	ScopesKey = "aether.auth.scopes"
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

// SetSessionID records the authenticated session ID for downstream handlers.
func SetSessionID(c *gin.Context, sessionID string) {
	c.Set(SessionIDKey, sessionID)
}

// SessionID returns the authenticated session ID string from c.
func SessionID(c *gin.Context) (string, bool) {
	value, exists := c.Get(SessionIDKey)
	if !exists {
		return "", false
	}
	sessionID, ok := value.(string)
	return sessionID, ok && sessionID != ""
}

// SetAccessTokenID records the authenticated access token jti.
func SetAccessTokenID(c *gin.Context, tokenID string) {
	c.Set(AccessTokenIDKey, tokenID)
}

// AccessTokenID returns the authenticated access token jti from c.
func AccessTokenID(c *gin.Context) (string, bool) {
	value, exists := c.Get(AccessTokenIDKey)
	if !exists {
		return "", false
	}
	tokenID, ok := value.(string)
	return tokenID, ok && tokenID != ""
}

// SetScopes records the authenticated access-token scopes.
func SetScopes(c *gin.Context, scopes []string) {
	c.Set(ScopesKey, append([]string(nil), scopes...))
}

// Scopes returns the authenticated access-token scopes from c.
func Scopes(c *gin.Context) ([]string, bool) {
	value, exists := c.Get(ScopesKey)
	if !exists {
		return nil, false
	}
	scopes, ok := value.([]string)
	if !ok {
		return nil, false
	}
	return append([]string(nil), scopes...), true
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
