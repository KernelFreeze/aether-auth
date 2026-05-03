package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

// Server wraps go-webauthn with Aether's account and service-error contracts.
type Server struct {
	config Config
}

// New builds a WebAuthn relying party server.
func New(config Config) (*Server, error) {
	server := &Server{config: config}
	if _, err := server.webAuthn(config.RelyingPartyID); err != nil {
		return nil, err
	}
	return server, nil
}

// RegistrationBeginRequest starts a passkey registration ceremony.
type RegistrationBeginRequest struct {
	User                    User
	ExistingCredentials     []Credential
	RelyingPartyID          string
	UserVerification        UserVerificationRequirement
	AuthenticatorAttachment AuthenticatorAttachment
}

// RegistrationBeginResult contains client-safe options and stored challenge
// state for a passkey registration ceremony.
type RegistrationBeginResult struct {
	Options   json.RawMessage
	Challenge Challenge
}

// RegistrationFinishRequest finishes a passkey registration ceremony.
type RegistrationFinishRequest struct {
	User                User
	Challenge           Challenge
	CredentialName      string
	AttestationResponse []byte
	Now                 time.Time
}

// LoginBeginRequest starts a passkey assertion ceremony.
type LoginBeginRequest struct {
	User             User
	RelyingPartyID   string
	UserVerification UserVerificationRequirement
}

// LoginBeginResult contains client-safe options and stored challenge state for
// a passkey assertion ceremony.
type LoginBeginResult struct {
	Options   json.RawMessage
	Challenge Challenge
}

// LoginFinishRequest finishes a passkey assertion ceremony.
type LoginFinishRequest struct {
	User              User
	Challenge         Challenge
	AssertionResponse []byte
	Now               time.Time
}

// AssertionResult contains the verified credential and factor state from a
// passkey assertion.
type AssertionResult struct {
	Credential   Credential
	FactorCheck  auth.FactorCheck
	CloneWarning bool
	UserVerified bool
}

// BeginRegistration returns WebAuthn creation options and the challenge state
// that must be stored until finish.
func (s *Server) BeginRegistration(_ context.Context, req RegistrationBeginRequest) (RegistrationBeginResult, error) {
	if err := validateUser(req.User); err != nil {
		return RegistrationBeginResult{}, err
	}
	rpID := s.relyingPartyID(req.RelyingPartyID)
	web, err := s.webAuthn(rpID)
	if err != nil {
		return RegistrationBeginResult{}, err
	}

	credentials := req.ExistingCredentials
	if credentials == nil {
		credentials = req.User.Credentials
	}
	verification := req.UserVerification
	if verification == "" {
		verification = s.config.UserVerification
	}
	options, session, err := web.BeginRegistration(
		webUser{User: req.User},
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: req.AuthenticatorAttachment.protocol(),
			UserVerification:        verification.protocol(),
		}),
		gowebauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		gowebauthn.WithExclusions(credentialDescriptors(CredentialsForRelyingParty(credentials, rpID))),
	)
	if err != nil {
		return RegistrationBeginResult{}, mapWebAuthnError("begin webauthn registration", err)
	}

	payload, err := json.Marshal(options)
	if err != nil {
		return RegistrationBeginResult{}, fmt.Errorf("webauthn: marshal registration options: %w", err)
	}
	return RegistrationBeginResult{
		Options:   payload,
		Challenge: challengeFromSession(req.User.AccountID, web.Config.RPID, session),
	}, nil
}

// FinishRegistration verifies a client attestation response and returns the
// passkey material that should be persisted.
func (s *Server) FinishRegistration(_ context.Context, req RegistrationFinishRequest) (Credential, error) {
	if err := validateUser(req.User); err != nil {
		return Credential{}, err
	}
	if err := validateChallenge(req.Challenge, req.Now); err != nil {
		return Credential{}, err
	}
	if len(req.AttestationResponse) == 0 {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn attestation response is required", nil)
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.AttestationResponse))
	if err != nil {
		return Credential{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "parse webauthn attestation response", err)
	}
	web, err := s.webAuthn(req.Challenge.RelyingPartyID)
	if err != nil {
		return Credential{}, err
	}
	credential, err := web.CreateCredential(webUser{User: req.User}, req.Challenge.sessionData(), parsed)
	if err != nil {
		return Credential{}, mapWebAuthnError("finish webauthn registration", err)
	}

	now := normalizedNow(req.Now)
	return Credential{
		AccountID:               req.User.AccountID,
		KeyID:                   cloneBytes(credential.ID),
		PublicKey:               cloneBytes(credential.PublicKey),
		AttestationType:         credential.AttestationType,
		Transports:              append([]protocol.AuthenticatorTransport(nil), credential.Transport...),
		AAGUID:                  cloneBytes(credential.Authenticator.AAGUID),
		SignCount:               credential.Authenticator.SignCount,
		RelyingPartyID:          web.Config.RPID,
		UserVerified:            credential.Flags.UserVerified,
		BackupEligible:          credential.Flags.BackupEligible,
		BackedUp:                credential.Flags.BackupState,
		AuthenticatorAttachment: authenticatorAttachmentFromProtocol(credential.Authenticator.Attachment),
		DisplayName:             strings.TrimSpace(req.CredentialName),
		Verified:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
	}, nil
}

// BeginLogin returns WebAuthn request options and the challenge state that must
// be stored until finish.
func (s *Server) BeginLogin(_ context.Context, req LoginBeginRequest) (LoginBeginResult, error) {
	if err := validateUser(req.User); err != nil {
		return LoginBeginResult{}, err
	}
	rpID := s.relyingPartyID(req.RelyingPartyID)
	web, err := s.webAuthn(rpID)
	if err != nil {
		return LoginBeginResult{}, err
	}
	credentials := CredentialsForRelyingParty(req.User.Credentials, rpID)
	if len(credentials) == 0 {
		return LoginBeginResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "account has no usable webauthn credentials", nil)
	}
	verification := req.UserVerification
	if verification == "" {
		verification = s.config.UserVerification
	}

	options, session, err := web.BeginLogin(
		webUser{User: req.User, credentials: credentials},
		gowebauthn.WithUserVerification(verification.protocol()),
	)
	if err != nil {
		return LoginBeginResult{}, mapWebAuthnError("begin webauthn login", err)
	}
	payload, err := json.Marshal(options)
	if err != nil {
		return LoginBeginResult{}, fmt.Errorf("webauthn: marshal login options: %w", err)
	}
	return LoginBeginResult{
		Options:   payload,
		Challenge: challengeFromSession(req.User.AccountID, web.Config.RPID, session),
	}, nil
}

// FinishLogin verifies a WebAuthn assertion response and returns the updated
// passkey state.
func (s *Server) FinishLogin(_ context.Context, req LoginFinishRequest) (AssertionResult, error) {
	if err := validateUser(req.User); err != nil {
		return AssertionResult{}, err
	}
	if err := validateChallenge(req.Challenge, req.Now); err != nil {
		return AssertionResult{}, err
	}
	if len(req.AssertionResponse) == 0 {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn assertion response is required", nil)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.AssertionResponse))
	if err != nil {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "parse webauthn assertion response", err)
	}
	web, err := s.webAuthn(req.Challenge.RelyingPartyID)
	if err != nil {
		return AssertionResult{}, err
	}
	webCredential, err := web.ValidateLogin(
		webUser{User: req.User, credentials: CredentialsForRelyingParty(req.User.Credentials, req.Challenge.RelyingPartyID)},
		req.Challenge.sessionData(),
		parsed,
	)
	if err != nil {
		return AssertionResult{}, mapWebAuthnError("finish webauthn login", err)
	}

	credential, ok := FindCredentialByKeyID(req.User.Credentials, webCredential.ID)
	if !ok {
		return AssertionResult{}, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "webauthn credential does not belong to account", nil)
	}
	now := normalizedNow(req.Now)
	credential.SignCount = webCredential.Authenticator.SignCount
	credential.UserVerified = webCredential.Flags.UserVerified
	credential.BackupEligible = webCredential.Flags.BackupEligible
	credential.BackedUp = webCredential.Flags.BackupState
	credential.LastUsedAt = now
	credential.UpdatedAt = now

	result := AssertionResult{
		Credential: credential,
		FactorCheck: auth.FactorCheck{
			Kind:             account.FactorKindPasskey,
			VerifiedAt:       now,
			ChallengeBinding: req.Challenge.Challenge,
		},
		CloneWarning: webCredential.Authenticator.CloneWarning,
		UserVerified: webCredential.Flags.UserVerified,
	}
	if result.CloneWarning {
		return result, auth.NewServiceError(auth.ErrorKindInvalidCredentials, "webauthn sign count did not advance", nil)
	}
	return result, nil
}

func (s *Server) webAuthn(rpID string) (*gowebauthn.WebAuthn, error) {
	if s == nil {
		return nil, auth.NewServiceError(auth.ErrorKindInternal, "webauthn server is nil", nil)
	}
	config := s.config
	rpID = strings.TrimSpace(rpID)
	if rpID == "" {
		rpID = strings.TrimSpace(config.RelyingPartyID)
	}
	if rpID == "" {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn relying party id is required", nil)
	}
	name := strings.TrimSpace(config.RelyingPartyName)
	if name == "" {
		name = defaultRelyingPartyName
	}
	origins := cleanOrigins(config.RelyingPartyOrigins)
	if len(origins) == 0 {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn relying party origins are required", nil)
	}

	web, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         name,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: config.UserVerification.protocol(),
		},
		Timeouts: gowebauthn.TimeoutsConfig{
			Login: gowebauthn.TimeoutConfig{
				Enforce:    config.EnforceTimeouts,
				Timeout:    config.LoginTimeout,
				TimeoutUVD: config.LoginTimeout,
			},
			Registration: gowebauthn.TimeoutConfig{
				Enforce:    config.EnforceTimeouts,
				Timeout:    config.RegistrationTimeout,
				TimeoutUVD: config.RegistrationTimeout,
			},
		},
	})
	if err != nil {
		return nil, auth.NewServiceError(auth.ErrorKindMalformedInput, "configure webauthn relying party", err)
	}
	return web, nil
}

func (s *Server) relyingPartyID(override string) string {
	if value := strings.TrimSpace(override); value != "" {
		return value
	}
	if s == nil {
		return ""
	}
	return strings.TrimSpace(s.config.RelyingPartyID)
}

func validateUser(user User) error {
	if user.AccountID.IsZero() {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn account id is required", nil)
	}
	if strings.TrimSpace(user.Username) == "" {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn username is required", nil)
	}
	return nil
}

func validateChallenge(challenge Challenge, now time.Time) error {
	if challenge.Challenge == "" || len(challenge.UserHandle) == 0 || strings.TrimSpace(challenge.RelyingPartyID) == "" {
		return auth.NewServiceError(auth.ErrorKindMalformedInput, "webauthn challenge is incomplete", nil)
	}
	now = normalizedNow(now)
	if !challenge.ExpiresAt.IsZero() && account.IsExpired(now, challenge.ExpiresAt) {
		return auth.NewServiceError(auth.ErrorKindExpiredChallenge, "webauthn challenge expired", nil)
	}
	return nil
}

func credentialDescriptors(credentials []gowebauthn.Credential) []protocol.CredentialDescriptor {
	descriptors := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, credential := range credentials {
		descriptors = append(descriptors, credential.Descriptor())
	}
	return descriptors
}

func cleanOrigins(values []string) []string {
	origins := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			origins = append(origins, trimmed)
		}
	}
	return origins
}

func normalizedNow(now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	return account.NormalizeTimestamp(now)
}

func mapWebAuthnError(action string, err error) error {
	if err == nil {
		return nil
	}
	var protocolErr *protocol.Error
	if errors.As(err, &protocolErr) {
		details := strings.ToLower(protocolErr.Details + " " + protocolErr.DevInfo)
		switch {
		case strings.Contains(details, "expired"):
			return auth.NewServiceError(auth.ErrorKindExpiredChallenge, action, err)
		case strings.Contains(details, "challenge"):
			return auth.NewServiceError(auth.ErrorKindInvalidCredentials, action, err)
		}
	}
	return auth.NewServiceError(auth.ErrorKindInvalidCredentials, action, err)
}
