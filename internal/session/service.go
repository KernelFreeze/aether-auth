// Package session issues login sessions, access tokens, refresh tokens, and
// partial MFA sessions.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/paseto"
)

const (
	defaultAccessTTL       = 15 * time.Minute
	defaultRefreshSliding  = 30 * 24 * time.Hour
	defaultRefreshAbsolute = 90 * 24 * time.Hour
	defaultPartialTTL      = 2 * time.Minute
	randomTokenBytes       = 32
	sessionKindFull        = "full"
	sessionKindPartial     = "partial"
	sessionStatusActive    = "active"
	sessionStatusRevoked   = "revoked"
)

// Config holds session and token defaults.
type Config struct {
	Issuer          string
	DefaultAudience []string
	DefaultScopes   []string
	AccessTTL       time.Duration
	RefreshSliding  time.Duration
	RefreshAbsolute time.Duration
	PartialTTL      time.Duration
	RevocationTTL   time.Duration
}

// ConfigFrom adapts the process configuration to the session service config.
func ConfigFrom(cfg *config.Config) Config {
	if cfg == nil {
		return Config{}
	}
	return Config{
		Issuer:          cfg.Issuer.URL,
		DefaultAudience: cfg.Issuer.Audiences,
		DefaultScopes:   cfg.OAuth.DefaultScopes,
		AccessTTL:       cfg.Session.AccessTTL,
		RefreshSliding:  cfg.Session.RefreshSliding,
		RefreshAbsolute: cfg.Session.RefreshAbsolute,
		PartialTTL:      cfg.Session.PartialSessionTTL,
		RevocationTTL:   cfg.Session.RevocationCacheTTL,
	}
}

// Store persists session records and token hashes.
type Store interface {
	CreateFullSession(context.Context, FullSessionRecord) error
	CreatePartialSession(context.Context, PartialSessionRecord) error
	GetActiveSession(context.Context, account.SessionID, time.Time) (SessionRecord, error)
	ListActiveSessions(context.Context, account.AccountID, time.Time) ([]AccountSessionRecord, error)
	RevokeAccountSessions(context.Context, AccountSessionsRevocation) ([]SessionRecord, error)
	RevokeSession(context.Context, SessionRevocation) (SessionRecord, error)
	RotateRefreshToken(context.Context, RefreshTokenRotation) (RefreshTokenRotationResult, error)
}

// AccessTokenRevocationCache stores short-lived revoked access-token IDs.
type AccessTokenRevocationCache interface {
	RevokeAccessToken(context.Context, string, time.Duration) error
	IsAccessTokenRevoked(context.Context, string) (bool, error)
}

// TokenIssuer creates PASETO tokens for session results.
type TokenIssuer interface {
	IssueAccessToken(context.Context, paseto.IssueRequest) (string, error)
	IssuePartialSessionToken(context.Context, paseto.IssueRequest) (string, error)
}

// IDGenerator creates persisted session IDs.
type IDGenerator interface {
	NewSessionID() (account.SessionID, error)
	NewRefreshTokenID() (uuid.UUID, error)
}

// FullSessionRecord is the complete storage write for a full login session.
type FullSessionRecord struct {
	Session      SessionRecord
	UserAgent    UserAgentRecord
	Factors      []FactorRecord
	RefreshToken RefreshTokenRecord
}

// PartialSessionRecord is the storage write for an MFA-bound partial session.
type PartialSessionRecord struct {
	Session   SessionRecord
	UserAgent UserAgentRecord
	Factors   []FactorRecord
}

// SessionRecord contains the persisted session metadata.
type SessionRecord struct {
	ID          account.SessionID
	AccountID   account.AccountID
	ClientID    account.ClientID
	Kind        string
	Status      string
	TokenID     string
	UserAgentID string
	IP          string
	ExpiresAt   time.Time
}

// AccountSessionRecord is the store view used for account-owned session APIs.
type AccountSessionRecord struct {
	ID        account.SessionID
	AccountID account.AccountID
	ClientID  account.ClientID
	IP        string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// UserAgentRecord contains normalized device metadata for a session.
type UserAgentRecord struct {
	FingerprintID string
	IP            string
	Description   string
	Headers       json.RawMessage
}

// FactorRecord records one factor proven during a login flow.
type FactorRecord struct {
	SessionID        account.SessionID
	Kind             account.FactorKind
	ChallengeBinding string
	VerifiedAt       time.Time
	Metadata         json.RawMessage
}

// RefreshTokenRecord contains a persisted refresh-token hash.
type RefreshTokenRecord struct {
	ID                uuid.UUID
	SessionID         account.SessionID
	ParentID          uuid.UUID
	ClientID          account.ClientID
	TokenHash         []byte
	Scopes            []string
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
}

// RefreshTokenRotation contains the token hashes and policy inputs needed to
// rotate a refresh token atomically.
type RefreshTokenRotation struct {
	TokenHash         []byte
	NewRefreshTokenID uuid.UUID
	NewTokenHash      []byte
	NewAccessTokenID  string
	RotatedAt         time.Time
	RefreshSliding    time.Duration
}

// RefreshTokenRotationResult is the session state needed to issue replacement
// client tokens after a refresh token is rotated.
type RefreshTokenRotationResult struct {
	Session      SessionRecord
	Factors      []FactorRecord
	RefreshToken RefreshTokenRecord
}

// RefreshSessionRequest contains the opaque refresh token presented by a client.
type RefreshSessionRequest struct {
	RefreshToken string
	Now          time.Time
}

// RefreshSessionResult contains replacement session material after rotation.
type RefreshSessionResult struct {
	SessionID    account.SessionID
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// SessionRevocation identifies one session to revoke. AccountID scopes
// user-initiated revocation to the caller's account; a zero AccountID is
// reserved for administrative callers.
type SessionRevocation struct {
	SessionID account.SessionID
	AccountID account.AccountID
	RevokedAt time.Time
}

// AccountSessionsRevocation identifies all sessions for an account to revoke.
type AccountSessionsRevocation struct {
	AccountID account.AccountID
	RevokedAt time.Time
}

// RevokeSessionRequest revokes one session owned by the authenticated account.
type RevokeSessionRequest struct {
	SessionID account.SessionID
	AccountID account.AccountID
	Now       time.Time
}

// AdminRevokeSessionRequest revokes one session without an account ownership
// check. It is the service hook later organization-admin work can call.
type AdminRevokeSessionRequest struct {
	SessionID account.SessionID
	Now       time.Time
}

// RevokeAccountSessionsRequest revokes every full session for an account, such
// as after a password change or reset.
type RevokeAccountSessionsRequest struct {
	AccountID account.AccountID
	Now       time.Time
}

// RevokeSessionResult describes a revoked session.
type RevokeSessionResult struct {
	SessionID account.SessionID
	AccountID account.AccountID
	RevokedAt time.Time
}

// RevokeAccountSessionsResult describes the sessions revoked for one account.
type RevokeAccountSessionsResult struct {
	Sessions []RevokeSessionResult
}

// Service creates login sessions and token material.
type Service struct {
	store       Store
	tokens      TokenIssuer
	revocations AccessTokenRevocationCache
	random      io.Reader
	ids         IDGenerator
	clock       auth.Clock
	cfg         Config
}

var _ auth.SessionIssuer = (*Service)(nil)

// ServiceDeps contains collaborators for session issuance.
type ServiceDeps struct {
	Store       Store
	Tokens      TokenIssuer
	Revocations AccessTokenRevocationCache
	Random      io.Reader
	IDs         IDGenerator
	Clock       auth.Clock
	Config      Config
}

// NewService builds a session issuer.
func NewService(deps ServiceDeps) *Service {
	randomReader := deps.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	ids := deps.IDs
	if ids == nil {
		ids = UUIDGenerator{}
	}
	return &Service{
		store:       deps.Store,
		tokens:      deps.Tokens,
		revocations: deps.Revocations,
		random:      randomReader,
		ids:         ids,
		clock:       deps.Clock,
		cfg:         deps.Config,
	}
}

// IssueSession creates a persisted full session, a signed access token, and an
// opaque refresh token stored only by hash.
func (s *Service) IssueSession(ctx context.Context, req auth.SessionIssueRequest) (auth.SessionIssueResult, error) {
	if err := s.ready(); err != nil {
		return auth.SessionIssueResult{}, err
	}
	if req.AccountID.IsZero() {
		return auth.SessionIssueResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "session account id is required", nil)
	}

	now := s.now(req.Now)
	accessExpiresAt := now.Add(durationOrDefault(s.cfg.AccessTTL, defaultAccessTTL))
	sessionExpiresAt := now.Add(durationOrDefault(s.cfg.RefreshAbsolute, defaultRefreshAbsolute))
	refreshExpiresAt := now.Add(durationOrDefault(s.cfg.RefreshSliding, defaultRefreshSliding))
	if refreshExpiresAt.After(sessionExpiresAt) {
		refreshExpiresAt = sessionExpiresAt
	}

	sessionID, err := s.ids.NewSessionID()
	if err != nil {
		return auth.SessionIssueResult{}, fmt.Errorf("session: generate session id: %w", err)
	}
	refreshID, err := s.ids.NewRefreshTokenID()
	if err != nil {
		return auth.SessionIssueResult{}, fmt.Errorf("session: generate refresh token id: %w", err)
	}
	tokenID, err := s.randomToken()
	if err != nil {
		return auth.SessionIssueResult{}, fmt.Errorf("session: generate access token id: %w", err)
	}
	refreshToken, refreshHash, err := s.randomTokenWithHash()
	if err != nil {
		return auth.SessionIssueResult{}, fmt.Errorf("session: generate refresh token: %w", err)
	}

	scopes := stringsOrDefault(req.Scopes, s.cfg.DefaultScopes, []string{"openid", "profile"})
	audience := stringsOrDefault(req.Audience, s.cfg.DefaultAudience, nil)
	factors := normalizeFactors(req.VerifiedFactors)
	ip := normalizeIP(req.IP)
	userAgent := strings.TrimSpace(req.UserAgent)
	userAgentID := fingerprintUserAgent(ip, userAgent)

	accessToken, err := s.tokens.IssueAccessToken(ctx, paseto.IssueRequest{
		Claims: accessClaims(accessClaimInput{
			Issuer:    s.cfg.Issuer,
			AccountID: req.AccountID,
			SessionID: sessionID,
			ClientID:  req.ClientID,
			TokenID:   tokenID,
			Scopes:    scopes,
			Audience:  audience,
			Factors:   factors,
			IssuedAt:  now,
			ExpiresAt: accessExpiresAt,
		}),
		Implicit: implicitAssertion("access", req.AccountID, sessionID, req.ClientID),
	})
	if err != nil {
		return auth.SessionIssueResult{}, fmt.Errorf("session: issue access token: %w", err)
	}

	record := FullSessionRecord{
		Session: SessionRecord{
			ID:          sessionID,
			AccountID:   req.AccountID,
			ClientID:    req.ClientID,
			Kind:        sessionKindFull,
			Status:      sessionStatusActive,
			TokenID:     tokenID,
			UserAgentID: userAgentID,
			IP:          ip,
			ExpiresAt:   sessionExpiresAt,
		},
		UserAgent: UserAgentRecord{
			FingerprintID: userAgentID,
			IP:            ip,
			Description:   userAgent,
			Headers:       json.RawMessage(`{}`),
		},
		Factors: factorRecords(sessionID, factors, nil, now),
		RefreshToken: RefreshTokenRecord{
			ID:                refreshID,
			SessionID:         sessionID,
			ClientID:          req.ClientID,
			TokenHash:         refreshHash,
			Scopes:            scopes,
			ExpiresAt:         refreshExpiresAt,
			AbsoluteExpiresAt: sessionExpiresAt,
		},
	}
	if err := s.store.CreateFullSession(ctx, record); err != nil {
		return auth.SessionIssueResult{}, fmt.Errorf("session: persist full session: %w", err)
	}

	return auth.SessionIssueResult{
		SessionID:    sessionID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiresAt,
	}, nil
}

// IssuePartialSession creates a short-lived partial session for MFA checks.
func (s *Service) IssuePartialSession(ctx context.Context, req auth.PartialSessionIssueRequest) (auth.PartialSessionIssueResult, error) {
	if err := s.ready(); err != nil {
		return auth.PartialSessionIssueResult{}, err
	}
	if req.AccountID.IsZero() {
		return auth.PartialSessionIssueResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "partial session account id is required", nil)
	}

	now := s.now(req.Now)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = durationOrDefault(s.cfg.PartialTTL, defaultPartialTTL)
	}
	expiresAt := now.Add(ttl)

	sessionID, err := s.ids.NewSessionID()
	if err != nil {
		return auth.PartialSessionIssueResult{}, fmt.Errorf("session: generate partial session id: %w", err)
	}
	tokenID, err := s.randomToken()
	if err != nil {
		return auth.PartialSessionIssueResult{}, fmt.Errorf("session: generate partial token id: %w", err)
	}
	factors := normalizeFactors(req.VerifiedFactors)
	bindings := append([]string(nil), req.ChallengeBindings...)

	token, err := s.tokens.IssuePartialSessionToken(ctx, paseto.IssueRequest{
		Claims: partialClaims(partialClaimInput{
			Issuer:            s.cfg.Issuer,
			AccountID:         req.AccountID,
			SessionID:         sessionID,
			TokenID:           tokenID,
			Factors:           factors,
			ChallengeBindings: bindings,
			IssuedAt:          now,
			ExpiresAt:         expiresAt,
		}),
		Implicit: implicitAssertion("partial", req.AccountID, sessionID, account.ClientID{}),
	})
	if err != nil {
		return auth.PartialSessionIssueResult{}, fmt.Errorf("session: issue partial session token: %w", err)
	}

	record := PartialSessionRecord{
		Session: SessionRecord{
			ID:        sessionID,
			AccountID: req.AccountID,
			Kind:      sessionKindPartial,
			Status:    sessionStatusActive,
			TokenID:   tokenID,
			ExpiresAt: expiresAt,
		},
		Factors: factorRecords(sessionID, factors, bindings, now),
	}
	if err := s.store.CreatePartialSession(ctx, record); err != nil {
		return auth.PartialSessionIssueResult{}, fmt.Errorf("session: persist partial session: %w", err)
	}

	return auth.PartialSessionIssueResult{
		SessionID: sessionID,
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// RefreshSession rotates an opaque refresh token and issues replacement client
// tokens for the same persisted session.
func (s *Service) RefreshSession(ctx context.Context, req RefreshSessionRequest) (RefreshSessionResult, error) {
	if err := s.ready(); err != nil {
		return RefreshSessionResult{}, err
	}
	now := s.now(req.Now)
	presentedHash, err := hashRefreshToken(req.RefreshToken)
	if err != nil {
		return RefreshSessionResult{}, err
	}

	refreshToken, refreshHash, err := s.randomTokenWithHash()
	if err != nil {
		return RefreshSessionResult{}, fmt.Errorf("session: generate refresh token: %w", err)
	}
	refreshID, err := s.ids.NewRefreshTokenID()
	if err != nil {
		return RefreshSessionResult{}, fmt.Errorf("session: generate refresh token id: %w", err)
	}
	accessTokenID, err := s.randomToken()
	if err != nil {
		return RefreshSessionResult{}, fmt.Errorf("session: generate access token id: %w", err)
	}

	rotated, err := s.store.RotateRefreshToken(ctx, RefreshTokenRotation{
		TokenHash:         presentedHash,
		NewRefreshTokenID: refreshID,
		NewTokenHash:      refreshHash,
		NewAccessTokenID:  accessTokenID,
		RotatedAt:         now,
		RefreshSliding:    durationOrDefault(s.cfg.RefreshSliding, defaultRefreshSliding),
	})
	if err != nil {
		return RefreshSessionResult{}, err
	}
	if rotated.Session.ID.IsZero() || rotated.Session.AccountID.IsZero() {
		return RefreshSessionResult{}, auth.NewServiceError(auth.ErrorKindInternal, "rotated session is incomplete", nil)
	}

	accessExpiresAt := now.Add(durationOrDefault(s.cfg.AccessTTL, defaultAccessTTL))
	sessionExpiresAt := account.NormalizeTimestamp(rotated.Session.ExpiresAt)
	if !sessionExpiresAt.IsZero() && accessExpiresAt.After(sessionExpiresAt) {
		accessExpiresAt = sessionExpiresAt
	}

	scopes := stringsOrDefault(rotated.RefreshToken.Scopes, s.cfg.DefaultScopes, []string{"openid", "profile"})
	audience := stringsOrDefault(nil, s.cfg.DefaultAudience, nil)
	factors := factorKindsFromRecords(rotated.Factors)
	accessToken, err := s.tokens.IssueAccessToken(ctx, paseto.IssueRequest{
		Claims: accessClaims(accessClaimInput{
			Issuer:    s.cfg.Issuer,
			AccountID: rotated.Session.AccountID,
			SessionID: rotated.Session.ID,
			ClientID:  rotated.Session.ClientID,
			TokenID:   accessTokenID,
			Scopes:    scopes,
			Audience:  audience,
			Factors:   factors,
			IssuedAt:  now,
			ExpiresAt: accessExpiresAt,
		}),
		Implicit: implicitAssertion("access", rotated.Session.AccountID, rotated.Session.ID, rotated.Session.ClientID),
	})
	if err != nil {
		return RefreshSessionResult{}, fmt.Errorf("session: issue access token: %w", err)
	}

	return RefreshSessionResult{
		SessionID:    rotated.Session.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExpiresAt,
	}, nil
}

// ListAccountSessions returns the authenticated account's active full sessions.
func (s *Service) ListAccountSessions(ctx context.Context, accountID account.AccountID) ([]account.AccountSession, error) {
	if err := s.storeReady(); err != nil {
		return nil, err
	}
	if accountID.IsZero() {
		return nil, account.ErrInvalidSession
	}
	records, err := s.store.ListActiveSessions(ctx, accountID, s.now(time.Time{}))
	if err != nil {
		return nil, err
	}
	sessions := make([]account.AccountSession, 0, len(records))
	for _, record := range records {
		sessions = append(sessions, account.AccountSession{
			ID:        record.ID,
			AccountID: record.AccountID,
			ClientID:  record.ClientID,
			IP:        record.IP,
			UserAgent: record.UserAgent,
			CreatedAt: record.CreatedAt,
			ExpiresAt: record.ExpiresAt,
		})
	}
	return sessions, nil
}

// RevokeAccountSession revokes one active session owned by the authenticated account.
func (s *Service) RevokeAccountSession(ctx context.Context, accountID account.AccountID, sessionID account.SessionID) error {
	if accountID.IsZero() || sessionID.IsZero() {
		return account.ErrInvalidSession
	}
	_, err := s.RevokeSession(ctx, RevokeSessionRequest{
		SessionID: sessionID,
		AccountID: accountID,
	})
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return account.ErrSessionNotFound
	}
	if errors.Is(err, auth.ErrMalformedInput) {
		return account.ErrInvalidSession
	}
	return err
}

// RevokeSession revokes one session owned by account and caches its current
// access-token ID so middleware can reject it quickly.
func (s *Service) RevokeSession(ctx context.Context, req RevokeSessionRequest) (RevokeSessionResult, error) {
	if err := s.revocationReady(); err != nil {
		return RevokeSessionResult{}, err
	}
	if req.SessionID.IsZero() || req.AccountID.IsZero() {
		return RevokeSessionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "session and account id are required", nil)
	}
	now := s.now(req.Now)
	record, err := s.store.RevokeSession(ctx, SessionRevocation{
		SessionID: req.SessionID,
		AccountID: req.AccountID,
		RevokedAt: now,
	})
	if err != nil {
		return RevokeSessionResult{}, err
	}
	if err := s.cacheRevokedAccessToken(ctx, record.TokenID); err != nil {
		return RevokeSessionResult{}, err
	}
	return revocationResult(record, now), nil
}

// AdminRevokeSession revokes one session without an account ownership check.
func (s *Service) AdminRevokeSession(ctx context.Context, req AdminRevokeSessionRequest) (RevokeSessionResult, error) {
	if err := s.revocationReady(); err != nil {
		return RevokeSessionResult{}, err
	}
	if req.SessionID.IsZero() {
		return RevokeSessionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "session id is required", nil)
	}
	now := s.now(req.Now)
	record, err := s.store.RevokeSession(ctx, SessionRevocation{
		SessionID: req.SessionID,
		RevokedAt: now,
	})
	if err != nil {
		return RevokeSessionResult{}, err
	}
	if err := s.cacheRevokedAccessToken(ctx, record.TokenID); err != nil {
		return RevokeSessionResult{}, err
	}
	return revocationResult(record, now), nil
}

// RevokeAccountSessions revokes every active full session for an account. Use
// this after password changes or password-reset confirmation.
func (s *Service) RevokeAccountSessions(ctx context.Context, req RevokeAccountSessionsRequest) (RevokeAccountSessionsResult, error) {
	if err := s.revocationReady(); err != nil {
		return RevokeAccountSessionsResult{}, err
	}
	if req.AccountID.IsZero() {
		return RevokeAccountSessionsResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	now := s.now(req.Now)
	records, err := s.store.RevokeAccountSessions(ctx, AccountSessionsRevocation{
		AccountID: req.AccountID,
		RevokedAt: now,
	})
	if err != nil {
		return RevokeAccountSessionsResult{}, err
	}
	results := make([]RevokeSessionResult, 0, len(records))
	for _, record := range records {
		if err := s.cacheRevokedAccessToken(ctx, record.TokenID); err != nil {
			return RevokeAccountSessionsResult{}, err
		}
		results = append(results, revocationResult(record, now))
	}
	return RevokeAccountSessionsResult{Sessions: results}, nil
}

func (s *Service) ready() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session service is nil", nil)
	}
	if s.store == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session store is nil", nil)
	}
	if s.tokens == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session token issuer is nil", nil)
	}
	if s.random == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session random reader is nil", nil)
	}
	if s.ids == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session id generator is nil", nil)
	}
	return nil
}

func (s *Service) storeReady() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session service is nil", nil)
	}
	if s.store == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session store is nil", nil)
	}
	return nil
}

func (s *Service) revocationReady() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session service is nil", nil)
	}
	if s.store == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "session store is nil", nil)
	}
	return nil
}

func (s *Service) cacheRevokedAccessToken(ctx context.Context, tokenID string) error {
	if s.revocations == nil || strings.TrimSpace(tokenID) == "" {
		return nil
	}
	ttl := durationOrDefault(s.cfg.RevocationTTL, durationOrDefault(s.cfg.AccessTTL, defaultAccessTTL))
	if err := s.revocations.RevokeAccessToken(ctx, tokenID, ttl); err != nil {
		return fmt.Errorf("session: cache access token revocation: %w", err)
	}
	return nil
}

func (s *Service) now(requested time.Time) time.Time {
	if !requested.IsZero() {
		return account.NormalizeTimestamp(requested)
	}
	if s.clock != nil {
		return account.NormalizeTimestamp(s.clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}

func (s *Service) randomToken() (string, error) {
	raw := make([]byte, randomTokenBytes)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Service) randomTokenWithHash() (string, []byte, error) {
	raw := make([]byte, randomTokenBytes)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), sum[:], nil
}

func hashRefreshToken(token string) ([]byte, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "refresh token is required", nil)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != randomTokenBytes {
		return nil, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "refresh token is invalid", err)
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.String()
	}
	return value
}

func fingerprintUserAgent(ip, userAgent string) string {
	sum := sha256.Sum256([]byte(ip + "\x00" + strings.TrimSpace(userAgent)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func normalizeFactors(factors []account.FactorKind) []account.FactorKind {
	seen := make(map[account.FactorKind]struct{}, len(factors))
	normalized := make([]account.FactorKind, 0, len(factors))
	for _, factor := range factors {
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

func factorRecords(sessionID account.SessionID, factors []account.FactorKind, bindings []string, now time.Time) []FactorRecord {
	records := make([]FactorRecord, 0, len(factors))
	for i, factor := range factors {
		var binding string
		if i < len(bindings) {
			binding = bindings[i]
		}
		records = append(records, FactorRecord{
			SessionID:        sessionID,
			Kind:             factor,
			ChallengeBinding: binding,
			VerifiedAt:       now,
			Metadata:         json.RawMessage(`{}`),
		})
	}
	return records
}

type accessClaimInput struct {
	Issuer    string
	AccountID account.AccountID
	SessionID account.SessionID
	ClientID  account.ClientID
	TokenID   string
	Scopes    []string
	Audience  []string
	Factors   []account.FactorKind
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func accessClaims(in accessClaimInput) map[string]any {
	claims := map[string]any{
		"sub":     in.AccountID.String(),
		"sid":     in.SessionID.String(),
		"jti":     in.TokenID,
		"iat":     account.NormalizeTimestamp(in.IssuedAt),
		"exp":     account.NormalizeTimestamp(in.ExpiresAt),
		"scope":   strings.Join(in.Scopes, " "),
		"factors": factorStrings(in.Factors),
	}
	if in.Issuer != "" {
		claims["iss"] = in.Issuer
	}
	if len(in.Audience) > 0 {
		claims["aud"] = append([]string(nil), in.Audience...)
	}
	if !in.ClientID.IsZero() {
		claims["client_id"] = in.ClientID.String()
	}
	return claims
}

type partialClaimInput struct {
	Issuer            string
	AccountID         account.AccountID
	SessionID         account.SessionID
	TokenID           string
	Factors           []account.FactorKind
	ChallengeBindings []string
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

func partialClaims(in partialClaimInput) map[string]any {
	claims := map[string]any{
		"typ":                "partial_session",
		"sub":                in.AccountID.String(),
		"sid":                in.SessionID.String(),
		"jti":                in.TokenID,
		"iat":                account.NormalizeTimestamp(in.IssuedAt),
		"exp":                account.NormalizeTimestamp(in.ExpiresAt),
		"factors":            factorStrings(in.Factors),
		"challenge_bindings": append([]string(nil), in.ChallengeBindings...),
	}
	if in.Issuer != "" {
		claims["iss"] = in.Issuer
	}
	return claims
}

func factorStrings(factors []account.FactorKind) []string {
	values := make([]string, 0, len(factors))
	for _, factor := range factors {
		values = append(values, factor.String())
	}
	return values
}

func factorKindsFromRecords(records []FactorRecord) []account.FactorKind {
	factors := make([]account.FactorKind, 0, len(records))
	for _, record := range records {
		if record.Kind.Valid() {
			factors = append(factors, record.Kind)
		}
	}
	return normalizeFactors(factors)
}

func implicitAssertion(kind string, accountID account.AccountID, sessionID account.SessionID, clientID account.ClientID) []byte {
	parts := []string{kind, accountID.String(), sessionID.String()}
	if !clientID.IsZero() {
		parts = append(parts, clientID.String())
	}
	return []byte(strings.Join(parts, "\x00"))
}

func stringsOrDefault(values []string, defaults []string, fallback []string) []string {
	for _, source := range [][]string{values, defaults, fallback} {
		cleaned := cleanStrings(source)
		if len(cleaned) > 0 {
			return cleaned
		}
	}
	return nil
}

func cleanStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func durationOrDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func revocationResult(record SessionRecord, revokedAt time.Time) RevokeSessionResult {
	return RevokeSessionResult{
		SessionID: record.ID,
		AccountID: record.AccountID,
		RevokedAt: account.NormalizeTimestamp(revokedAt),
	}
}

// UUIDGenerator creates UUIDv7 session and refresh-token IDs.
type UUIDGenerator struct{}

// NewSessionID returns a new UUIDv7 session ID.
func (UUIDGenerator) NewSessionID() (account.SessionID, error) {
	return account.NewSessionID()
}

// NewRefreshTokenID returns a new UUIDv7 refresh-token ID.
func (UUIDGenerator) NewRefreshTokenID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("session: generate refresh token id: %w", err)
	}
	return id, nil
}
