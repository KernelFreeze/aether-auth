package passwordreset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const (
	resetRequestEndpoint = "/auth/reset-password/request"
	defaultTokenTTL      = 20 * time.Minute
	resetTokenBytes      = 32
)

// Service owns password-reset request behavior.
type Service struct {
	store         Store
	emailQueue    EmailQueue
	ids           IDGenerator
	random        io.Reader
	clock         auth.Clock
	tokenTTL      time.Duration
	publicBaseURL string
}

// Deps holds reset-request collaborators.
type ServiceDeps struct {
	Store         Store
	EmailQueue    EmailQueue
	IDs           IDGenerator
	Random        io.Reader
	Clock         auth.Clock
	TokenTTL      time.Duration
	PublicBaseURL string
}

// Store persists reset tokens and resolves reset targets.
type Store interface {
	LookupResetTarget(context.Context, ResetLookup) (ResetTarget, error)
	CreateResetToken(context.Context, ResetTokenDraft) error
}

// EmailQueue queues password-reset email delivery.
type EmailQueue interface {
	EnqueuePasswordResetEmail(context.Context, ResetEmail) error
}

// IDGenerator creates password-reset token IDs.
type IDGenerator interface {
	NewResetTokenID() (uuid.UUID, error)
}

// UUIDGenerator creates UUIDv7 password-reset token IDs.
type UUIDGenerator struct{}

// NewResetTokenID returns a new UUIDv7 reset-token ID.
func (UUIDGenerator) NewResetTokenID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("passwordreset: generate reset token id: %w", err)
	}
	return id, nil
}

// NewService builds a password-reset request service.
func NewService(deps ServiceDeps) *Service {
	ids := deps.IDs
	if ids == nil {
		ids = UUIDGenerator{}
	}
	randomReader := deps.Random
	if randomReader == nil {
		randomReader = rand.Reader
	}
	ttl := deps.TokenTTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	return &Service{
		store:         deps.Store,
		emailQueue:    deps.EmailQueue,
		ids:           ids,
		random:        randomReader,
		clock:         deps.Clock,
		tokenTTL:      ttl,
		publicBaseURL: deps.PublicBaseURL,
	}
}

// RequestReset creates a single-use reset token when the account exists.
func (s *Service) RequestReset(ctx context.Context, req RequestResetRequest) (RequestResetResult, error) {
	if err := s.ready(); err != nil {
		return RequestResetResult{}, err
	}
	lookup, err := resetLookupFrom(req)
	if err != nil {
		return RequestResetResult{}, err
	}

	target, err := s.store.LookupResetTarget(ctx, lookup)
	if err != nil {
		if isResetMiss(err) {
			return RequestResetResult{}, nil
		}
		return RequestResetResult{}, err
	}

	token, tokenHash, err := s.newToken()
	if err != nil {
		return RequestResetResult{}, err
	}
	id, err := s.ids.NewResetTokenID()
	if err != nil {
		return RequestResetResult{}, err
	}
	resetURL, err := resetURL(s.publicBaseURL, token)
	if err != nil {
		return RequestResetResult{}, err
	}

	now := account.NormalizeTimestamp(s.now())
	expiresAt := now.Add(s.tokenTTL)
	if err := s.store.CreateResetToken(ctx, ResetTokenDraft{
		ID:            id,
		AccountID:     target.AccountID,
		TokenHash:     tokenHash,
		RequestedByIP: req.IP,
		UserAgent:     req.UserAgent,
		ExpiresAt:     expiresAt,
	}); err != nil {
		return RequestResetResult{}, err
	}
	if err := s.emailQueue.EnqueuePasswordResetEmail(ctx, ResetEmail{
		AccountID: target.AccountID,
		To:        target.Email,
		ResetURL:  resetURL,
		ExpiresAt: expiresAt,
		RequestID: req.RequestID,
	}); err != nil {
		return RequestResetResult{}, err
	}
	return RequestResetResult{}, nil
}

func (s *Service) ready() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset service is nil", nil)
	}
	if s.store == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset store is nil", nil)
	}
	if s.emailQueue == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset email queue is nil", nil)
	}
	if s.ids == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset id generator is nil", nil)
	}
	if s.random == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset random reader is nil", nil)
	}
	if strings.TrimSpace(s.publicBaseURL) == "" {
		return auth.NewServiceError(auth.ErrorKindInternal, "password reset public base url is empty", nil)
	}
	return nil
}

func (s *Service) newToken() (string, []byte, error) {
	tokenBytes := make([]byte, resetTokenBytes)
	if _, err := io.ReadFull(s.random, tokenBytes); err != nil {
		return "", nil, fmt.Errorf("passwordreset: generate reset token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

func (s *Service) now() time.Time {
	if s.clock != nil {
		return s.clock.Now()
	}
	return time.Now()
}

func resetLookupFrom(req RequestResetRequest) (ResetLookup, error) {
	values := 0
	for _, value := range []string{req.Identifier, req.Username, req.Email} {
		if strings.TrimSpace(value) != "" {
			values++
		}
	}
	if values != 1 {
		return ResetLookup{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "exactly one reset identifier is required", nil)
	}

	switch {
	case strings.TrimSpace(req.Identifier) != "":
		identifier := normalizeIdentifier(req.Identifier)
		if strings.Contains(identifier, "@") {
			return ResetLookup{Email: identifier}, nil
		}
		return ResetLookup{Username: identifier}, nil
	case strings.TrimSpace(req.Username) != "":
		return ResetLookup{Username: normalizeIdentifier(req.Username)}, nil
	default:
		return ResetLookup{Email: normalizeIdentifier(req.Email)}, nil
	}
}

func resetURL(publicBaseURL, token string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(publicBaseURL))
	if err != nil {
		return "", auth.NewServiceError(auth.ErrorKindInternal, "password reset public base url is invalid", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return "", auth.NewServiceError(auth.ErrorKindInternal, "password reset public base url scheme is invalid", nil)
	}
	if base.Host == "" {
		return "", auth.NewServiceError(auth.ErrorKindInternal, "password reset public base url host is empty", nil)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/reset-password"
	query := base.Query()
	query.Set("token", token)
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isResetMiss(err error) bool {
	kind, ok := auth.ErrorKindOf(err)
	return ok && (kind == auth.ErrorKindInvalidCredentials || kind == auth.ErrorKindLockedAccount)
}

// RequestResetRequest is the public reset request.
type RequestResetRequest struct {
	Identifier string
	Username   string
	Email      string
	IP         string
	UserAgent  string
	RequestID  string
}

// RequestResetResult is intentionally empty; callers always receive the same
// public response.
type RequestResetResult struct{}

// ResetLookup identifies the account that should receive reset instructions.
type ResetLookup struct {
	Username string
	Email    string
}

// ResetTarget is the account and email address used for reset delivery.
type ResetTarget struct {
	AccountID account.AccountID
	Username  string
	Email     string
}

// ResetTokenDraft is the token row stored for a reset request.
type ResetTokenDraft struct {
	ID            uuid.UUID
	AccountID     account.AccountID
	TokenHash     []byte
	RequestedByIP string
	UserAgent     string
	ExpiresAt     time.Time
}

// ResetEmail is queued for async reset-email delivery.
type ResetEmail struct {
	AccountID account.AccountID
	To        string
	ResetURL  string
	ExpiresAt time.Time
	RequestID string
}
