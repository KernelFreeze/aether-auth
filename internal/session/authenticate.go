package session

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	gopaseto "aidanwoods.dev/go-paseto"
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/authctx"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
)

const (
	errorIDAccessInvalid       = "SESSION-AUTH-0001"
	errorIDAccessNotConfigured = "SESSION-AUTH-0002"
	errorIDAccessInternal      = "SESSION-AUTH-0003"
)

// AccessTokenVerifier verifies signed PASETO access tokens.
type AccessTokenVerifier interface {
	VerifyAccessToken(context.Context, string, []byte, ...paseto.Rule) (*paseto.Token, error)
}

// AuthenticationDeps holds collaborators for access-token middleware.
type AuthenticationDeps struct {
	Tokens      AccessTokenVerifier
	Sessions    Store
	Revocations AccessTokenRevocationCache
	Clock       auth.Clock
	Issuer      string
}

// NewAuthenticationMiddleware authenticates bearer access tokens and stores
// verified account/session facts on the Gin context.
func NewAuthenticationMiddleware(deps AuthenticationDeps) gin.HandlerFunc {
	a := authenticator{deps: deps}
	return a.handle
}

type authenticator struct {
	deps AuthenticationDeps
}

type accessTokenClaims struct {
	AccountID account.AccountID
	SessionID account.SessionID
	ClientID  account.ClientID
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Scopes    []string
}

func (a authenticator) handle(c *gin.Context) {
	if a.deps.Tokens == nil || a.deps.Sessions == nil {
		writeSessionProblem(c, http.StatusNotImplemented, "authentication_not_configured", "Authentication not configured", "Authentication middleware is not wired.", errorIDAccessNotConfigured)
		c.Abort()
		return
	}

	raw, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		writeAccessTokenError(c, auth.ErrInvalidCredentials)
		return
	}

	claims, err := unsafeAccessTokenClaims(raw)
	if err != nil {
		writeAccessTokenError(c, err)
		return
	}
	if a.deps.Revocations != nil {
		revoked, err := a.deps.Revocations.IsAccessTokenRevoked(c.Request.Context(), claims.TokenID)
		if err != nil {
			writeAccessTokenError(c, err)
			return
		}
		if revoked {
			writeAccessTokenError(c, auth.ErrInvalidCredentials)
			return
		}
	}

	rules := make([]paseto.Rule, 0, 1)
	if strings.TrimSpace(a.deps.Issuer) != "" {
		rules = append(rules, gopaseto.IssuedBy(a.deps.Issuer))
	}
	if _, err := a.deps.Tokens.VerifyAccessToken(c.Request.Context(), raw, implicitAssertion("access", claims.AccountID, claims.SessionID, claims.ClientID), rules...); err != nil {
		writeAccessTokenError(c, auth.ErrInvalidCredentials)
		return
	}

	sessionRecord, err := a.deps.Sessions.GetActiveSession(c.Request.Context(), claims.SessionID, a.now())
	if err != nil {
		writeAccessTokenError(c, err)
		return
	}
	if sessionRecord.AccountID != claims.AccountID || sessionRecord.Kind != sessionKindFull || sessionRecord.Status != sessionStatusActive {
		writeAccessTokenError(c, auth.ErrInvalidCredentials)
		return
	}
	if !sessionRecord.ClientID.IsZero() && sessionRecord.ClientID != claims.ClientID {
		writeAccessTokenError(c, auth.ErrInvalidCredentials)
		return
	}

	authctx.SetAccountID(c, claims.AccountID.String())
	authctx.SetSessionID(c, claims.SessionID.String())
	authctx.SetAccessTokenID(c, claims.TokenID)
	authctx.SetScopes(c, claims.Scopes)
	authctx.SetReauthenticatedAt(c, account.NormalizeTimestamp(claims.IssuedAt))
	c.Next()
}

func (a authenticator) now() time.Time {
	if a.deps.Clock != nil {
		return account.NormalizeTimestamp(a.deps.Clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}

func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || strings.TrimSpace(fields[1]) == "" {
		return "", false
	}
	return fields[1], true
}

func unsafeAccessTokenClaims(raw string) (accessTokenClaims, error) {
	payload, err := unsafePASETOPublicPayload(raw)
	if err != nil {
		return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token is malformed", err)
	}
	var body struct {
		Subject  string    `json:"sub"`
		Session  string    `json:"sid"`
		Client   string    `json:"client_id"`
		TokenID  string    `json:"jti"`
		Type     string    `json:"typ"`
		IssuedAt time.Time `json:"iat"`
		Expires  time.Time `json:"exp"`
		Scope    string    `json:"scope"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token claims are malformed", err)
	}
	if body.Type != "" {
		return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token type is invalid", nil)
	}
	accountID, err := account.ParseAccountID(body.Subject)
	if err != nil {
		return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token subject is invalid", err)
	}
	sessionID, err := account.ParseSessionID(body.Session)
	if err != nil {
		return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token session is invalid", err)
	}
	var clientID account.ClientID
	if strings.TrimSpace(body.Client) != "" {
		clientID, err = account.ParseClientID(body.Client)
		if err != nil {
			return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token client is invalid", err)
		}
	}
	if strings.TrimSpace(body.TokenID) == "" || body.IssuedAt.IsZero() || body.Expires.IsZero() {
		return accessTokenClaims{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "access token required claims are missing", nil)
	}
	return accessTokenClaims{
		AccountID: accountID,
		SessionID: sessionID,
		ClientID:  clientID,
		TokenID:   body.TokenID,
		IssuedAt:  account.NormalizeTimestamp(body.IssuedAt),
		ExpiresAt: account.NormalizeTimestamp(body.Expires),
		Scopes:    strings.Fields(body.Scope),
	}, nil
}

func unsafePASETOPublicPayload(raw string) ([]byte, error) {
	body, ok := strings.CutPrefix(raw, "v4.public.")
	if !ok {
		return nil, errors.New("not a v4.public token")
	}
	payloadSegment, _, _ := strings.Cut(body, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, err
	}
	if len(decoded) <= ed25519.SignatureSize {
		return nil, errors.New("v4.public payload is missing")
	}
	return decoded[:len(decoded)-ed25519.SignatureSize], nil
}

func writeAccessTokenError(c *gin.Context, err error) {
	if errors.Is(err, auth.ErrInvalidCredentials) {
		writeSessionProblem(c, http.StatusUnauthorized, "invalid_access_token", "Invalid access token", "The access token is invalid.", errorIDAccessInvalid)
		c.Abort()
		return
	}
	if errors.Is(err, auth.ErrMalformedInput) {
		writeSessionProblem(c, http.StatusBadRequest, "invalid_access_token", "Invalid access token", "The access token is invalid.", errorIDAccessInvalid)
		c.Abort()
		return
	}
	writeSessionProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", errorIDAccessInternal)
	c.Abort()
}
