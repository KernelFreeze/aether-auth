package webauthn

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const (
	registrationChallengeProvider = "registration"
	defaultRegistrationTTL        = time.Minute
)

// RegistrationService coordinates passkey registration across the WebAuthn
// server, challenge store, and credential store.
type RegistrationService struct {
	server      *Server
	credentials CredentialStore
	challenges  auth.ChallengeStore
	ids         RegistrationIDGenerator
	clock       auth.Clock
	ttl         time.Duration
}

// RegistrationServiceDeps holds passkey registration collaborators.
type RegistrationServiceDeps struct {
	Server       *Server
	Credentials  CredentialStore
	Challenges   auth.ChallengeStore
	IDs          RegistrationIDGenerator
	Clock        auth.Clock
	ChallengeTTL time.Duration
}

// RegistrationIDGenerator creates IDs for stored passkey challenges and
// credentials.
type RegistrationIDGenerator interface {
	NewCredentialID() (account.CredentialID, error)
	NewChallengeID() (string, error)
}

// RegistrationStartRequest starts an account-owned passkey registration.
type RegistrationStartRequest struct {
	AccountID               account.AccountID
	SessionID               account.SessionID
	Username                string
	DisplayName             string
	RequestID               string
	UserVerification        UserVerificationRequirement
	AuthenticatorAttachment AuthenticatorAttachment
}

// RegistrationStartResult contains the client options and stored challenge ID.
type RegistrationStartResult struct {
	ChallengeID string
	Options     json.RawMessage
	ExpiresAt   time.Time
}

// RegistrationCompleteRequest finishes an account-owned passkey registration.
type RegistrationCompleteRequest struct {
	AccountID           account.AccountID
	SessionID           account.SessionID
	Username            string
	DisplayName         string
	ChallengeID         string
	CredentialName      string
	AttestationResponse json.RawMessage
	Now                 time.Time
}

// NewRegistrationService builds a passkey registration service.
func NewRegistrationService(deps RegistrationServiceDeps) *RegistrationService {
	ids := deps.IDs
	if ids == nil {
		ids = auth.UUIDGenerator{}
	}
	ttl := deps.ChallengeTTL
	if ttl <= 0 {
		ttl = defaultRegistrationTTL
	}
	return &RegistrationService{
		server:      deps.Server,
		credentials: deps.Credentials,
		challenges:  deps.Challenges,
		ids:         ids,
		clock:       deps.Clock,
		ttl:         ttl,
	}
}

// BeginRegistration generates public WebAuthn options and stores the matching
// one-time challenge.
func (s *RegistrationService) BeginRegistration(ctx context.Context, req RegistrationStartRequest) (RegistrationStartResult, error) {
	if err := s.ready(); err != nil {
		return RegistrationStartResult{}, err
	}
	user, err := registrationUser(req.AccountID, req.Username, req.DisplayName)
	if err != nil {
		return RegistrationStartResult{}, err
	}
	if req.SessionID.IsZero() {
		return RegistrationStartResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn registration session id is required", nil)
	}

	existing, err := s.credentials.ListCredentials(ctx, req.AccountID, "")
	if err != nil {
		return RegistrationStartResult{}, err
	}
	user.Credentials = existing
	begin, err := s.server.BeginRegistration(ctx, RegistrationBeginRequest{
		User:                    user,
		ExistingCredentials:     existing,
		UserVerification:        req.UserVerification,
		AuthenticatorAttachment: req.AuthenticatorAttachment,
	})
	if err != nil {
		return RegistrationStartResult{}, err
	}
	now := s.now()
	challenge := begin.Challenge
	challenge.CreatedAt = now
	if challenge.ExpiresAt.IsZero() || !challenge.ExpiresAt.After(now) {
		challenge.ExpiresAt = now.Add(s.ttl)
	}
	challengeID, err := s.ids.NewChallengeID()
	if err != nil {
		return RegistrationStartResult{}, fmt.Errorf("webauthn: generate challenge id: %w", err)
	}
	payload, err := challenge.Encode()
	if err != nil {
		return RegistrationStartResult{}, fmt.Errorf("webauthn: encode registration challenge: %w", err)
	}
	if err := s.challenges.SaveChallenge(ctx, auth.StoredChallenge{
		ID:             challengeID,
		Purpose:        auth.ChallengePurposeWebAuthn,
		AccountID:      req.AccountID,
		Provider:       registrationChallengeProvider,
		SessionBinding: req.SessionID.String(),
		RequestID:      req.RequestID,
		Payload:        payload,
		ExpiresAt:      challenge.ExpiresAt,
		CreatedAt:      now,
	}); err != nil {
		return RegistrationStartResult{}, err
	}
	return RegistrationStartResult{
		ChallengeID: challengeID,
		Options:     append(json.RawMessage(nil), begin.Options...),
		ExpiresAt:   challenge.ExpiresAt,
	}, nil
}

// FinishRegistration consumes a stored challenge, verifies the attestation,
// and persists the resulting passkey credential.
func (s *RegistrationService) FinishRegistration(ctx context.Context, req RegistrationCompleteRequest) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	user, err := registrationUser(req.AccountID, req.Username, req.DisplayName)
	if err != nil {
		return Credential{}, err
	}
	if req.SessionID.IsZero() || strings.TrimSpace(req.ChallengeID) == "" {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn registration session and challenge id are required", nil)
	}
	if len(req.AttestationResponse) == 0 {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn attestation response is required", nil)
	}

	stored, err := s.challenges.ConsumeChallenge(ctx, auth.ChallengeLookup{
		ID:             strings.TrimSpace(req.ChallengeID),
		Purpose:        auth.ChallengePurposeWebAuthn,
		SessionBinding: req.SessionID.String(),
		Provider:       registrationChallengeProvider,
	})
	if err != nil {
		return Credential{}, err
	}
	if stored.AccountID != req.AccountID {
		return Credential{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "webauthn registration challenge account mismatch", nil)
	}
	challenge, err := DecodeChallenge(stored.Payload)
	if err != nil {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "decode webauthn registration challenge", err)
	}
	if challenge.AccountID != req.AccountID {
		return Credential{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "webauthn registration challenge user mismatch", nil)
	}

	now := req.Now
	if now.IsZero() {
		now = s.now()
	}
	credential, err := s.server.FinishRegistration(ctx, RegistrationFinishRequest{
		User:                user,
		Challenge:           challenge,
		CredentialName:      req.CredentialName,
		AttestationResponse: append([]byte(nil), req.AttestationResponse...),
		Now:                 now,
	})
	if err != nil {
		return Credential{}, err
	}
	credential.ID, err = s.ids.NewCredentialID()
	if err != nil {
		return Credential{}, fmt.Errorf("webauthn: generate credential id: %w", err)
	}
	return s.credentials.CreateCredential(ctx, credential)
}

func (s *RegistrationService) ready() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "webauthn registration service is nil", nil)
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

func (s *RegistrationService) now() time.Time {
	if s.clock != nil {
		return account.NormalizeTimestamp(s.clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}

func registrationUser(accountID account.AccountID, username, displayName string) (User, error) {
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
