package webauthn

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const (
	loginChallengeProvider = "login"
	defaultLoginTTL        = time.Minute
)

// LoginService coordinates passkey assertion ceremonies across the WebAuthn
// server, challenge store, credential store, and audit log.
type LoginService struct {
	server      *Server
	credentials CredentialStore
	challenges  auth.ChallengeStore
	audit       auth.AuditWriter
	ids         LoginIDGenerator
	clock       auth.Clock
	ttl         time.Duration
}

// LoginServiceDeps holds passkey login collaborators.
type LoginServiceDeps struct {
	Server       *Server
	Credentials  CredentialStore
	Challenges   auth.ChallengeStore
	Audit        auth.AuditWriter
	IDs          LoginIDGenerator
	Clock        auth.Clock
	ChallengeTTL time.Duration
}

// LoginIDGenerator creates IDs for stored passkey assertion challenges.
type LoginIDGenerator interface {
	NewChallengeID() (string, error)
}

// LoginStartRequest starts a passkey assertion ceremony.
type LoginStartRequest struct {
	AccountID        account.AccountID
	Username         string
	DisplayName      string
	RequestID        string
	SessionBinding   string
	UserVerification UserVerificationRequirement
}

// LoginStartResult contains the client options and stored challenge ID.
type LoginStartResult struct {
	ChallengeID string
	Options     json.RawMessage
	ExpiresAt   time.Time
}

// LoginCompleteRequest finishes a passkey assertion ceremony.
type LoginCompleteRequest struct {
	AccountID         account.AccountID
	Username          string
	DisplayName       string
	ChallengeID       string
	SessionBinding    string
	AssertionResponse json.RawMessage
	RequestID         string
	IP                string
	UserAgent         string
	Now               time.Time
}

// NewLoginService builds a passkey login service.
func NewLoginService(deps LoginServiceDeps) *LoginService {
	ids := deps.IDs
	if ids == nil {
		ids = auth.UUIDGenerator{}
	}
	ttl := deps.ChallengeTTL
	if ttl <= 0 {
		ttl = defaultLoginTTL
	}
	return &LoginService{
		server:      deps.Server,
		credentials: deps.Credentials,
		challenges:  deps.Challenges,
		audit:       deps.Audit,
		ids:         ids,
		clock:       deps.Clock,
		ttl:         ttl,
	}
}

// BeginLogin generates public WebAuthn assertion options and stores the
// matching one-time challenge.
func (s *LoginService) BeginLogin(ctx context.Context, req LoginStartRequest) (LoginStartResult, error) {
	if err := s.ready(); err != nil {
		return LoginStartResult{}, err
	}
	user, err := ceremonyUser(req.AccountID, req.Username, req.DisplayName)
	if err != nil {
		return LoginStartResult{}, err
	}

	credentials, err := s.credentials.ListCredentials(ctx, req.AccountID, "")
	if err != nil {
		return LoginStartResult{}, err
	}
	user.Credentials = credentials
	begin, err := s.server.BeginLogin(ctx, LoginBeginRequest{
		User:             user,
		UserVerification: req.UserVerification,
	})
	if err != nil {
		return LoginStartResult{}, err
	}

	now := s.now()
	challenge := begin.Challenge
	challenge.CreatedAt = now
	if challenge.ExpiresAt.IsZero() || !challenge.ExpiresAt.After(now) {
		challenge.ExpiresAt = now.Add(s.ttl)
	}
	challengeID, err := s.ids.NewChallengeID()
	if err != nil {
		return LoginStartResult{}, fmt.Errorf("webauthn: generate login challenge id: %w", err)
	}
	payload, err := challenge.Encode()
	if err != nil {
		return LoginStartResult{}, fmt.Errorf("webauthn: encode login challenge: %w", err)
	}
	if err := s.challenges.SaveChallenge(ctx, auth.StoredChallenge{
		ID:             challengeID,
		Purpose:        auth.ChallengePurposeWebAuthn,
		AccountID:      req.AccountID,
		Provider:       loginChallengeProvider,
		SessionBinding: strings.TrimSpace(req.SessionBinding),
		RequestID:      req.RequestID,
		Payload:        payload,
		ExpiresAt:      challenge.ExpiresAt,
		CreatedAt:      now,
	}); err != nil {
		return LoginStartResult{}, err
	}
	return LoginStartResult{
		ChallengeID: challengeID,
		Options:     append(json.RawMessage(nil), begin.Options...),
		ExpiresAt:   challenge.ExpiresAt,
	}, nil
}

// FinishLogin consumes a stored challenge, verifies the assertion, and stores
// the updated credential sign-count state.
func (s *LoginService) FinishLogin(ctx context.Context, req LoginCompleteRequest) (AssertionResult, error) {
	if err := s.ready(); err != nil {
		return AssertionResult{}, err
	}
	user, err := ceremonyUser(req.AccountID, req.Username, req.DisplayName)
	if err != nil {
		return AssertionResult{}, err
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn login challenge id is required", nil)
	}
	if len(req.AssertionResponse) == 0 {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn assertion response is required", nil)
	}

	stored, err := s.challenges.ConsumeChallenge(ctx, auth.ChallengeLookup{
		ID:             strings.TrimSpace(req.ChallengeID),
		Purpose:        auth.ChallengePurposeWebAuthn,
		SessionBinding: strings.TrimSpace(req.SessionBinding),
		Provider:       loginChallengeProvider,
	})
	if err != nil {
		return AssertionResult{}, err
	}
	if stored.AccountID != req.AccountID {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "webauthn login challenge account mismatch", nil)
	}
	challenge, err := DecodeChallenge(stored.Payload)
	if err != nil {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "decode webauthn login challenge", err)
	}
	if challenge.AccountID != req.AccountID {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "webauthn login challenge user mismatch", nil)
	}

	credentials, err := s.credentials.ListCredentials(ctx, req.AccountID, challenge.RelyingPartyID)
	if err != nil {
		return AssertionResult{}, err
	}
	user.Credentials = credentials
	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	result, err := s.server.FinishLogin(ctx, LoginFinishRequest{
		User:              user,
		Challenge:         challenge,
		AssertionResponse: append([]byte(nil), req.AssertionResponse...),
		Now:               now,
	})
	if result.CloneWarning {
		if auditErr := s.writeCloneWarning(ctx, req, result.Credential, now); auditErr != nil {
			return AssertionResult{}, auditErr
		}
	}
	if err != nil {
		return AssertionResult{}, err
	}

	updated, err := s.credentials.UpdateCredentialAssertion(ctx, result.Credential)
	if err != nil {
		return AssertionResult{}, err
	}
	result.Credential = updated
	return result, nil
}

func (s *LoginService) ready() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn login service is nil", nil)
	}
	if s.server == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn server is nil", nil)
	}
	if s.credentials == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn credential store is nil", nil)
	}
	if s.challenges == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn challenge store is nil", nil)
	}
	if s.ids == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn id generator is nil", nil)
	}
	return nil
}

func (s *LoginService) writeCloneWarning(ctx context.Context, req LoginCompleteRequest, credential Credential, now time.Time) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.WriteAuditEvent(ctx, auth.AuditEvent{
		Type:         auth.AuditEventWebAuthnCloneWarning,
		AccountID:    req.AccountID,
		CredentialID: credential.ID,
		RequestID:    req.RequestID,
		IP:           req.IP,
		UserAgent:    req.UserAgent,
		OccurredAt:   account.NormalizeTimestamp(now),
		Attributes: map[string]string{
			"method":        account.CredentialKindWebAuthn.String(),
			"outcome":       "clone_warning",
			"sign_count":    strconv.FormatUint(uint64(credential.SignCount), 10),
			"user_verified": strconv.FormatBool(credential.UserVerified),
		},
	})
}

func (s *LoginService) now() time.Time {
	if s.clock != nil {
		return account.NormalizeTimestamp(s.clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}

func ceremonyUser(accountID account.AccountID, username, displayName string) (User, error) {
	if accountID.IsZero() {
		return User{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn account id is required", nil)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn username is required", nil)
	}
	return User{
		AccountID:   accountID,
		Username:    username,
		DisplayName: strings.TrimSpace(displayName),
	}, nil
}
