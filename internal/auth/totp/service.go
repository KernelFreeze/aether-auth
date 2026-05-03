package totp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const (
	defaultRecoveryCodeCount  = 10
	defaultRecoveryCodeLength = 12
	defaultRecoveryAlphabet   = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// Config controls TOTP and recovery-code behavior.
type Config struct {
	Issuer               string
	SecretSize           int
	Digits               int
	Period               time.Duration
	Skew                 int
	RecoveryCodeCount    int
	RecoveryCodeLength   int
	RecoveryCodeAlphabet string
}

// Deps holds collaborators for TOTP enrollment and verification.
type Deps struct {
	Credentials   auth.CredentialRepository
	RecoveryCodes RecoveryCodeStore
	Hasher        auth.PasswordHasher
	Box           auth.SecretBox
	Attempts      AttemptStore
	Audit         auth.AuditWriter
	Clock         auth.Clock
	Random        io.Reader
	Config        Config
}

// Service owns TOTP credentials and recovery codes.
type Service struct {
	credentials   auth.CredentialRepository
	recoveryCodes RecoveryCodeStore
	hasher        auth.PasswordHasher
	box           auth.SecretBox
	attempts      AttemptStore
	audit         auth.AuditWriter
	clock         auth.Clock
	random        io.Reader
	config        Config
}

var _ auth.AuthMethod = (*Service)(nil)

// New builds a TOTP service.
func New(deps Deps) *Service {
	return &Service{
		credentials:   deps.Credentials,
		recoveryCodes: deps.RecoveryCodes,
		hasher:        deps.Hasher,
		box:           deps.Box,
		attempts:      deps.Attempts,
		audit:         deps.Audit,
		clock:         deps.Clock,
		random:        deps.Random,
		config:        deps.Config,
	}
}

// Kind returns the credential kind verified by this method.
func (s *Service) Kind() account.CredentialKind {
	return account.CredentialKindTOTP
}

// Begin is a no-op for TOTP because enrollment creates the secret explicitly.
func (s *Service) Begin(context.Context, auth.BeginRequest) (auth.BeginResult, error) {
	return auth.BeginResult{}, nil
}

// Enroll creates an unverified TOTP credential and returns the one-time setup
// material the client needs to show a QR code.
func (s *Service) Enroll(ctx context.Context, req EnrollRequest) (Enrollment, error) {
	if err := s.readyForTOTPWrite(); err != nil {
		return Enrollment{}, err
	}
	if req.AccountID.IsZero() {
		return Enrollment{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	accountName := strings.TrimSpace(req.AccountName)
	if accountName == "" {
		return Enrollment{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "totp account name is required", nil)
	}

	secret, err := GenerateSecret(s.randomReader(), s.secretSize())
	if err != nil {
		return Enrollment{}, err
	}
	issuer := defaultString(req.Issuer, s.issuer())
	uri, err := ProvisioningURI(ProvisioningURIRequest{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      secret,
		Digits:      s.digits(),
		Period:      s.period(),
	})
	if err != nil {
		return Enrollment{}, err
	}
	payload, err := s.sealSecret(ctx, req.AccountID, storedTOTPPayload{
		Secret:        secret,
		Algorithm:     algorithmSHA1,
		Digits:        s.digits(),
		PeriodSeconds: int(s.period() / time.Second),
	})
	if err != nil {
		return Enrollment{}, err
	}

	credential, err := s.credentials.CreateCredential(ctx, auth.CredentialDraft{
		AccountID:        req.AccountID,
		Kind:             account.CredentialKindTOTP,
		EncryptedPayload: payload,
		Verified:         false,
	})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{
		AccountID:       req.AccountID,
		CredentialID:    credential.ID,
		Secret:          secret,
		ProvisioningURI: uri,
	}, nil
}

// ConfirmEnrollment verifies the first TOTP code and marks the credential ready.
func (s *Service) ConfirmEnrollment(ctx context.Context, req ConfirmEnrollmentRequest) (auth.CredentialSnapshot, error) {
	if err := s.readyForTOTPWrite(); err != nil {
		return auth.CredentialSnapshot{}, err
	}
	if req.AccountID.IsZero() || req.CredentialID.IsZero() {
		return auth.CredentialSnapshot{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account and credential ids are required", nil)
	}

	credential, payload, err := s.loadTOTPCredential(ctx, req.AccountID, req.CredentialID, false)
	if err != nil {
		return auth.CredentialSnapshot{}, err
	}
	now := s.now()
	ok, err := ValidateCode(payload.Secret, req.Code, now, payload.Digits, time.Duration(payload.PeriodSeconds)*time.Second, s.skew())
	if err != nil {
		return auth.CredentialSnapshot{}, err
	}
	if !ok {
		return auth.CredentialSnapshot{}, s.recordFailure(ctx, AttemptFailure{
			AccountID:    req.AccountID,
			CredentialID: credential.ID,
			Factor:       account.FactorKindTOTP,
			OccurredAt:   now,
			Endpoint:     req.Endpoint,
		})
	}

	verified := true
	updated, err := s.credentials.UpdateCredential(ctx, auth.CredentialUpdate{
		CredentialID: credential.ID,
		Verified:     &verified,
		LastUsedAt:   now,
	})
	if err != nil {
		return auth.CredentialSnapshot{}, err
	}
	if err := s.recordSuccess(ctx, AttemptSuccess{
		AccountID:    req.AccountID,
		CredentialID: credential.ID,
		Factor:       account.FactorKindTOTP,
		OccurredAt:   now,
		Endpoint:     req.Endpoint,
	}); err != nil {
		return auth.CredentialSnapshot{}, err
	}
	return updated, nil
}

// Verify implements auth.AuthMethod for TOTP second-factor checks.
func (s *Service) Verify(ctx context.Context, req auth.VerifyRequest) (auth.AuthResult, error) {
	accountID := req.AccountHint
	if req.PartialSession != nil && !req.PartialSession.AccountID.IsZero() {
		accountID = req.PartialSession.AccountID
	}
	check, credential, err := s.VerifyTOTP(ctx, VerifyTOTPRequest{
		AccountID:        accountID,
		Code:             codeFromCredentialInput(req.CredentialInput),
		IP:               req.IP,
		UserAgent:        req.UserAgent,
		ChallengeBinding: req.ChallengeID,
		RequestID:        req.RequestID,
	})
	if err != nil {
		return auth.AuthResult{}, err
	}
	return auth.AuthResult{
		AccountID:          accountID,
		CredentialID:       credential.ID,
		VerifiedFactors:    auth.VerifiedFactorKinds([]auth.FactorCheck{check}),
		FactorChecks:       []auth.FactorCheck{check},
		MFAStatus:          auth.MFAStatusSatisfied,
		CredentialVerified: true,
	}, nil
}

// VerifyTOTP checks a verified TOTP credential and records MFA lockout state.
func (s *Service) VerifyTOTP(ctx context.Context, req VerifyTOTPRequest) (auth.FactorCheck, auth.CredentialSnapshot, error) {
	if err := s.readyForTOTPVerify(); err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}
	if req.AccountID.IsZero() {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	credential, payload, err := s.loadTOTPCredential(ctx, req.AccountID, req.CredentialID, true)
	if err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}

	now := s.now()
	ok, err := ValidateCode(payload.Secret, req.Code, now, payload.Digits, time.Duration(payload.PeriodSeconds)*time.Second, s.skew())
	if err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}
	if !ok {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, s.recordFailure(ctx, AttemptFailure{
			AccountID:    req.AccountID,
			CredentialID: credential.ID,
			Factor:       account.FactorKindTOTP,
			RequestID:    req.RequestID,
			IP:           req.IP,
			UserAgent:    req.UserAgent,
			OccurredAt:   now,
			Endpoint:     req.Endpoint,
		})
	}

	updated, err := s.credentials.UpdateCredential(ctx, auth.CredentialUpdate{
		CredentialID: credential.ID,
		LastUsedAt:   now,
	})
	if err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}
	if err := s.recordSuccess(ctx, AttemptSuccess{
		AccountID:    req.AccountID,
		CredentialID: credential.ID,
		Factor:       account.FactorKindTOTP,
		IP:           req.IP,
		UserAgent:    req.UserAgent,
		OccurredAt:   now,
		Endpoint:     req.Endpoint,
	}); err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}
	return auth.FactorCheck{
		Kind:             account.FactorKindTOTP,
		VerifiedAt:       now,
		ChallengeBinding: req.ChallengeBinding,
	}, updated, nil
}

func (s *Service) loadTOTPCredential(ctx context.Context, accountID account.AccountID, credentialID account.CredentialID, requireVerified bool) (auth.CredentialSnapshot, storedTOTPPayload, error) {
	lookup := auth.CredentialLookup{CredentialID: credentialID}
	if credentialID.IsZero() {
		lookup = auth.CredentialLookup{AccountID: accountID, Kind: account.CredentialKindTOTP}
	}
	credential, err := s.credentials.LookupCredential(ctx, lookup)
	if err != nil {
		return auth.CredentialSnapshot{}, storedTOTPPayload{}, auth.ErrInvalidCredentials
	}
	if credential.AccountID != accountID || credential.Kind != account.CredentialKindTOTP {
		return auth.CredentialSnapshot{}, storedTOTPPayload{}, auth.ErrInvalidCredentials
	}
	if requireVerified && !credential.Verified {
		return auth.CredentialSnapshot{}, storedTOTPPayload{}, auth.ErrInvalidCredentials
	}
	payload, err := s.openSecret(ctx, credential)
	if err != nil {
		return auth.CredentialSnapshot{}, storedTOTPPayload{}, err
	}
	return credential, payload, nil
}

func (s *Service) sealSecret(ctx context.Context, accountID account.AccountID, payload storedTOTPPayload) ([]byte, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("totp: marshal secret payload: %w", err)
	}
	sealed, err := s.box.Seal(ctx, auth.SecretBoxSealRequest{
		Plaintext:      plaintext,
		AssociatedData: totpAAD(accountID),
	})
	if err != nil {
		return nil, fmt.Errorf("totp: seal secret payload: %w", err)
	}
	out, err := json.Marshal(sealedCredentialPayload{
		KeyID:      sealed.KeyID,
		Nonce:      sealed.Nonce,
		Ciphertext: sealed.Ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("totp: marshal sealed payload: %w", err)
	}
	return out, nil
}

func (s *Service) openSecret(ctx context.Context, credential auth.CredentialSnapshot) (storedTOTPPayload, error) {
	var sealed sealedCredentialPayload
	if err := json.Unmarshal(credential.EncryptedPayload, &sealed); err != nil || len(sealed.Ciphertext) == 0 {
		return storedTOTPPayload{}, auth.ErrInvalidCredentials
	}
	plaintext, err := s.box.Open(ctx, auth.SecretBoxOpenRequest{
		Payload: auth.SecretBoxPayload{
			KeyID:      sealed.KeyID,
			Nonce:      sealed.Nonce,
			Ciphertext: sealed.Ciphertext,
		},
		AssociatedData: totpAAD(credential.AccountID),
	})
	if err != nil {
		return storedTOTPPayload{}, auth.ErrInvalidCredentials
	}
	var payload storedTOTPPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil || normalizeSecret(payload.Secret) == "" {
		return storedTOTPPayload{}, auth.ErrInvalidCredentials
	}
	if payload.Digits <= 0 {
		payload.Digits = s.digits()
	}
	if payload.PeriodSeconds <= 0 {
		payload.PeriodSeconds = int(s.period() / time.Second)
	}
	return payload, nil
}

func (s *Service) recordFailure(ctx context.Context, failure AttemptFailure) error {
	if failure.OccurredAt.IsZero() {
		failure.OccurredAt = s.now()
	}
	var result AttemptResult
	if s.attempts != nil {
		var err error
		result, err = s.attempts.RecordFailure(ctx, failure)
		if err != nil {
			return err
		}
	}
	locked := !result.LockedUntil.IsZero() && result.LockedUntil.After(failure.OccurredAt)
	if err := s.writeFailureAudit(ctx, failure, locked); err != nil {
		return err
	}
	if locked {
		return auth.ErrLockedAccount
	}
	return auth.ErrInvalidCredentials
}

func (s *Service) writeFailureAudit(ctx context.Context, failure AttemptFailure, locked bool) error {
	if s.audit == nil {
		return nil
	}
	outcome := "invalid"
	if locked {
		outcome = "locked"
	}
	attributes := map[string]string{
		"factor":  failure.Factor.String(),
		"outcome": outcome,
	}
	if endpoint := strings.TrimSpace(failure.Endpoint); endpoint != "" {
		attributes["endpoint"] = endpoint
	}
	return s.audit.WriteAuditEvent(ctx, auth.AuditEvent{
		Type:         auth.AuditEventMFAFailed,
		AccountID:    failure.AccountID,
		CredentialID: failure.CredentialID,
		RequestID:    failure.RequestID,
		IP:           auditIP(failure.IP),
		UserAgent:    failure.UserAgent,
		OccurredAt:   failure.OccurredAt,
		Attributes:   attributes,
	})
}

func auditIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

func (s *Service) recordSuccess(ctx context.Context, success AttemptSuccess) error {
	if s.attempts == nil {
		return nil
	}
	if success.OccurredAt.IsZero() {
		success.OccurredAt = s.now()
	}
	return s.attempts.RecordSuccess(ctx, success)
}

func (s *Service) readyForTOTPWrite() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "totp service is nil", nil)
	}
	if s.credentials == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "totp credential repository is nil", nil)
	}
	if s.box == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "totp secret box is nil", nil)
	}
	return nil
}

func (s *Service) readyForTOTPVerify() error {
	return s.readyForTOTPWrite()
}

func (s *Service) now() time.Time {
	if s != nil && s.clock != nil {
		return account.NormalizeTimestamp(s.clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}

func (s *Service) randomReader() io.Reader {
	if s != nil && s.random != nil {
		return s.random
	}
	return rand.Reader
}

func (s *Service) issuer() string {
	if s != nil {
		return defaultString(s.config.Issuer, defaultIssuer)
	}
	return defaultIssuer
}

func (s *Service) secretSize() int {
	if s != nil && s.config.SecretSize > 0 {
		return s.config.SecretSize
	}
	return defaultSecretSize
}

func (s *Service) digits() int {
	if s != nil && s.config.Digits > 0 {
		return s.config.Digits
	}
	return defaultDigits
}

func (s *Service) period() time.Duration {
	if s != nil && s.config.Period > 0 {
		return s.config.Period
	}
	return defaultPeriod
}

func (s *Service) skew() int {
	if s != nil && s.config.Skew > 0 {
		return s.config.Skew
	}
	return defaultSkew
}

func (s *Service) recoveryCodeCount() int {
	if s != nil && s.config.RecoveryCodeCount > 0 {
		return s.config.RecoveryCodeCount
	}
	return defaultRecoveryCodeCount
}

func (s *Service) recoveryCodeLength() int {
	if s != nil && s.config.RecoveryCodeLength > 0 {
		return s.config.RecoveryCodeLength
	}
	return defaultRecoveryCodeLength
}

func (s *Service) recoveryCodeAlphabet() string {
	if s != nil && strings.TrimSpace(s.config.RecoveryCodeAlphabet) != "" {
		return s.config.RecoveryCodeAlphabet
	}
	return defaultRecoveryAlphabet
}

func codeFromCredentialInput(input any) string {
	switch v := input.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case map[string]any:
		code, _ := v["code"].(string)
		return code
	default:
		return ""
	}
}

func totpAAD(accountID account.AccountID) []byte {
	return []byte(`{"account_id":"` + accountID.String() + `","kind":"totp"}`)
}

type storedTOTPPayload struct {
	Secret        string `json:"secret"`
	Algorithm     string `json:"algorithm"`
	Digits        int    `json:"digits"`
	PeriodSeconds int    `json:"period_seconds"`
}

type sealedCredentialPayload struct {
	KeyID      string `json:"key_id,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Ciphertext []byte `json:"ciphertext"`
}

// EnrollRequest describes TOTP enrollment for an account.
type EnrollRequest struct {
	AccountID   account.AccountID
	Issuer      string
	AccountName string
}

// Enrollment contains the one-time setup data returned to the client.
type Enrollment struct {
	AccountID       account.AccountID
	CredentialID    account.CredentialID
	Secret          string
	ProvisioningURI string
}

// ConfirmEnrollmentRequest verifies the first setup code.
type ConfirmEnrollmentRequest struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Code         string
	Endpoint     string
}

// VerifyTOTPRequest verifies a TOTP code during MFA.
type VerifyTOTPRequest struct {
	AccountID        account.AccountID
	CredentialID     account.CredentialID
	Code             string
	IP               netip.Addr
	UserAgent        string
	Endpoint         string
	RequestID        string
	ChallengeBinding string
}
