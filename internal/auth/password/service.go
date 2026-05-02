package password

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const defaultPartialSessionTTL = 2 * time.Minute

// Deps holds the collaborators needed for password set, change, and login.
type Deps struct {
	Credentials       auth.CredentialRepository
	Hasher            auth.PasswordHasher
	Policy            auth.PasswordPolicy
	Breaches          auth.BreachChecker
	Box               auth.SecretBox
	Attempts          AttemptStore
	Clock             auth.Clock
	PartialSessionTTL time.Duration
	DummyHash         auth.PasswordHash
}

// Service owns password credentials and implements auth.AuthMethod.
type Service struct {
	credentials       auth.CredentialRepository
	hasher            auth.PasswordHasher
	policy            auth.PasswordPolicy
	breaches          auth.BreachChecker
	box               auth.SecretBox
	attempts          AttemptStore
	clock             auth.Clock
	partialSessionTTL time.Duration
	dummyHash         auth.PasswordHash
}

var (
	_ auth.AuthMethod        = (*Service)(nil)
	_ auth.DummyPasswordWork = (*Service)(nil)
)

// New builds a password service.
func New(deps Deps) *Service {
	ttl := deps.PartialSessionTTL
	if ttl <= 0 {
		ttl = defaultPartialSessionTTL
	}
	return &Service{
		credentials:       deps.Credentials,
		hasher:            deps.Hasher,
		policy:            deps.Policy,
		breaches:          deps.Breaches,
		box:               deps.Box,
		attempts:          deps.Attempts,
		clock:             deps.Clock,
		partialSessionTTL: ttl,
		dummyHash:         deps.DummyHash,
	}
}

// Kind returns the credential kind verified by this method.
func (s *Service) Kind() account.CredentialKind {
	return account.CredentialKindPassword
}

// Begin is a no-op for immediate password verification.
func (s *Service) Begin(context.Context, auth.BeginRequest) (auth.BeginResult, error) {
	return auth.BeginResult{}, nil
}

// SetPassword validates, hashes, encrypts, and stores a password credential.
func (s *Service) SetPassword(ctx context.Context, req SetPasswordRequest) (auth.CredentialSnapshot, error) {
	if err := s.readyForPasswordWrite(); err != nil {
		return auth.CredentialSnapshot{}, err
	}
	if req.AccountID.IsZero() {
		return auth.CredentialSnapshot{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	password := normalizePasswordInput(req.Password)
	if password == "" {
		return auth.CredentialSnapshot{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "password is required", nil)
	}

	if err := s.checkPasswordPolicy(ctx, req, password); err != nil {
		return auth.CredentialSnapshot{}, err
	}

	hash, err := s.hasher.HashPassword(ctx, auth.PasswordHashRequest{
		Password:  password,
		AccountID: req.AccountID,
	})
	if err != nil {
		return auth.CredentialSnapshot{}, fmt.Errorf("password: hash password: %w", err)
	}
	payload, err := s.sealHash(ctx, req.AccountID, hash)
	if err != nil {
		return auth.CredentialSnapshot{}, err
	}

	if req.CredentialID.IsZero() {
		return s.credentials.CreateCredential(ctx, auth.CredentialDraft{
			AccountID:        req.AccountID,
			Kind:             account.CredentialKindPassword,
			EncryptedPayload: payload,
			Verified:         true,
		})
	}

	current, err := s.credentials.LookupCredential(ctx, auth.CredentialLookup{CredentialID: req.CredentialID})
	if err != nil {
		return auth.CredentialSnapshot{}, err
	}
	if current.AccountID != req.AccountID || current.Kind != account.CredentialKindPassword {
		return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
	}
	verified := true
	return s.credentials.UpdateCredential(ctx, auth.CredentialUpdate{
		CredentialID:     req.CredentialID,
		EncryptedPayload: payload,
		Verified:         &verified,
	})
}

// Verify checks a password credential and returns session instructions.
func (s *Service) Verify(ctx context.Context, req auth.VerifyRequest) (auth.AuthResult, error) {
	if err := s.readyForVerify(); err != nil {
		return auth.AuthResult{}, err
	}
	if req.AccountHint.IsZero() {
		return auth.AuthResult{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account hint is required", nil)
	}
	password, err := passwordFromCredentialInput(req.CredentialInput)
	if err != nil {
		return auth.AuthResult{}, err
	}

	credential, err := s.credentials.LookupCredential(ctx, auth.CredentialLookup{
		AccountID: req.AccountHint,
		Kind:      account.CredentialKindPassword,
	})
	if err != nil {
		return auth.AuthResult{}, auth.ErrInvalidCredentials
	}
	stored, err := s.openHash(ctx, credential)
	if err != nil {
		return auth.AuthResult{}, err
	}

	verified, err := s.hasher.VerifyPassword(ctx, auth.PasswordVerifyRequest{
		Password:  password,
		Hash:      stored,
		AccountID: req.AccountHint,
	})
	if err != nil {
		return auth.AuthResult{}, fmt.Errorf("password: verify password: %w", err)
	}
	now := s.now()
	if !verified.Matched {
		return auth.AuthResult{}, s.recordFailure(ctx, req, credential, now)
	}

	factorChecks := successfulPasswordFactorChecks(now)
	if err := s.recordSuccess(ctx, req, credential, now); err != nil {
		return auth.AuthResult{}, err
	}
	if err := s.updateSuccessfulCredential(ctx, credential, password, verified.NeedsRehash, now); err != nil {
		return auth.AuthResult{}, err
	}

	mfaStatus := auth.MFAStatusNotRequired
	session := auth.SessionIssueInstructions{Issue: true}
	if req.MFARequired {
		mfaStatus = auth.MFAStatusRequired
		session.Partial = true
		session.ExpiresAt = now.Add(s.partialSessionTTL)
	}
	return auth.AuthResult{
		AccountID:          req.AccountHint,
		CredentialID:       credential.ID,
		VerifiedFactors:    auth.VerifiedFactorKinds(factorChecks),
		FactorChecks:       factorChecks,
		MFAStatus:          mfaStatus,
		Session:            session,
		CredentialVerified: true,
	}, nil
}

// RunDummyPasswordWork performs equivalent hash work for missing accounts.
func (s *Service) RunDummyPasswordWork(ctx context.Context, req auth.DummyPasswordWorkRequest) error {
	if s == nil || s.hasher == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password hasher is nil", nil)
	}
	password, err := passwordFromCredentialInput(req.CredentialInput)
	if err != nil {
		return err
	}
	if s.dummyHash.PHCString != "" {
		_, err := s.hasher.VerifyPassword(ctx, auth.PasswordVerifyRequest{
			Password: password,
			Hash:     s.dummyHash,
		})
		return err
	}
	_, err = s.hasher.HashPassword(ctx, auth.PasswordHashRequest{Password: password})
	return err
}

// SetPasswordRequest describes a password set or replacement operation.
type SetPasswordRequest struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Password     string
	Username     string
	Email        string
}

type credentialInput struct {
	Password string `json:"password"`
}

type storedPasswordPayload struct {
	Hash auth.PasswordHash `json:"hash"`
}

type sealedPasswordPayload struct {
	KeyID      string `json:"key_id,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Ciphertext []byte `json:"ciphertext"`
}

func (s *Service) checkPasswordPolicy(ctx context.Context, req SetPasswordRequest, password string) error {
	if s.policy != nil {
		result, err := s.policy.CheckPasswordPolicy(ctx, auth.PasswordPolicyRequest{
			Password:  password,
			AccountID: req.AccountID,
			Username:  req.Username,
			Email:     req.Email,
		})
		if err != nil {
			return fmt.Errorf("password: check policy: %w", err)
		}
		if !result.Allowed {
			return auth.NewServiceError(auth.ErrorKindPolicyDenied, strings.Join(result.Violations, ","), nil)
		}
	}
	if s.breaches == nil {
		return nil
	}
	result, err := s.breaches.CheckPasswordBreach(ctx, auth.PasswordBreachRequest{
		Password:  password,
		AccountID: req.AccountID,
	})
	if err != nil {
		return fmt.Errorf("password: check breach corpus: %w", err)
	}
	if result.Breached {
		return auth.NewServiceError(auth.ErrorKindPolicyDenied, "password appears in breach corpus", nil)
	}
	return nil
}

func (s *Service) updateSuccessfulCredential(ctx context.Context, credential auth.CredentialSnapshot, password string, needsRehash bool, now time.Time) error {
	update := auth.CredentialUpdate{
		CredentialID: credential.ID,
		LastUsedAt:   now,
	}
	if needsRehash {
		hash, err := s.hasher.HashPassword(ctx, auth.PasswordHashRequest{
			Password:  password,
			AccountID: credential.AccountID,
		})
		if err != nil {
			return fmt.Errorf("password: rehash password: %w", err)
		}
		payload, err := s.sealHash(ctx, credential.AccountID, hash)
		if err != nil {
			return err
		}
		update.EncryptedPayload = payload
	}
	_, err := s.credentials.UpdateCredential(ctx, update)
	return err
}

func (s *Service) recordFailure(ctx context.Context, req auth.VerifyRequest, credential auth.CredentialSnapshot, now time.Time) error {
	if s.attempts == nil {
		return auth.ErrInvalidCredentials
	}
	result, err := s.attempts.RecordFailure(ctx, AttemptFailure{
		AccountID:    req.AccountHint,
		CredentialID: credential.ID,
		Username:     req.Username,
		IP:           req.IP,
		OccurredAt:   now,
		FactorCheck: auth.FactorCheck{
			Kind:     account.FactorKindPassword,
			FailedAt: now,
		},
	})
	if err != nil {
		return err
	}
	if !result.LockedUntil.IsZero() && result.LockedUntil.After(now) {
		return auth.ErrLockedAccount
	}
	return auth.ErrInvalidCredentials
}

func (s *Service) recordSuccess(ctx context.Context, req auth.VerifyRequest, credential auth.CredentialSnapshot, now time.Time) error {
	if s.attempts == nil {
		return nil
	}
	return s.attempts.RecordSuccess(ctx, AttemptSuccess{
		AccountID:    req.AccountHint,
		CredentialID: credential.ID,
		Username:     req.Username,
		IP:           req.IP,
		OccurredAt:   now,
		FactorChecks: successfulPasswordFactorChecks(now),
	})
}

func successfulPasswordFactorChecks(now time.Time) []auth.FactorCheck {
	return []auth.FactorCheck{
		{Kind: account.FactorKindUser, VerifiedAt: now},
		{Kind: account.FactorKindPassword, VerifiedAt: now},
	}
}

func (s *Service) sealHash(ctx context.Context, accountID account.AccountID, hash auth.PasswordHash) ([]byte, error) {
	plaintext, err := json.Marshal(storedPasswordPayload{Hash: hash})
	if err != nil {
		return nil, fmt.Errorf("password: marshal password payload: %w", err)
	}
	sealed, err := s.box.Seal(ctx, auth.SecretBoxSealRequest{
		Plaintext:      plaintext,
		AssociatedData: passwordAAD(accountID),
	})
	if err != nil {
		return nil, fmt.Errorf("password: seal password payload: %w", err)
	}
	payload, err := json.Marshal(sealedPasswordPayload{
		KeyID:      sealed.KeyID,
		Nonce:      sealed.Nonce,
		Ciphertext: sealed.Ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("password: marshal sealed payload: %w", err)
	}
	return payload, nil
}

func (s *Service) openHash(ctx context.Context, credential auth.CredentialSnapshot) (auth.PasswordHash, error) {
	var sealed sealedPasswordPayload
	if err := json.Unmarshal(credential.EncryptedPayload, &sealed); err != nil || len(sealed.Ciphertext) == 0 {
		return auth.PasswordHash{}, auth.ErrInvalidCredentials
	}
	plaintext, err := s.box.Open(ctx, auth.SecretBoxOpenRequest{
		Payload: auth.SecretBoxPayload{
			KeyID:      sealed.KeyID,
			Nonce:      sealed.Nonce,
			Ciphertext: sealed.Ciphertext,
		},
		AssociatedData: passwordAAD(credential.AccountID),
	})
	if err != nil {
		return auth.PasswordHash{}, auth.ErrInvalidCredentials
	}

	var payload storedPasswordPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Hash.PHCString == "" {
		return auth.PasswordHash{}, auth.ErrInvalidCredentials
	}
	return payload.Hash, nil
}

func passwordAAD(accountID account.AccountID) []byte {
	return []byte(`{"account_id":"` + accountID.String() + `","kind":"password"}`)
}

func passwordFromCredentialInput(input any) (string, error) {
	switch v := input.(type) {
	case string:
		if v == "" {
			return "", auth.NewServiceError(auth.ErrorKindMalformedInput, "password is required", nil)
		}
		return v, nil
	case []byte:
		if len(v) == 0 {
			return "", auth.NewServiceError(auth.ErrorKindMalformedInput, "password is required", nil)
		}
		return string(v), nil
	case credentialInput:
		return passwordFromCredentialInput(v.Password)
	case *credentialInput:
		if v == nil {
			return "", auth.NewServiceError(auth.ErrorKindMalformedInput, "password is required", nil)
		}
		return passwordFromCredentialInput(v.Password)
	case map[string]any:
		password, _ := v["password"].(string)
		return passwordFromCredentialInput(password)
	default:
		return "", auth.NewServiceError(auth.ErrorKindMalformedInput, "password input is unsupported", nil)
	}
}

func normalizePasswordInput(password string) string {
	return password
}

func (s *Service) readyForVerify() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password service is nil", nil)
	}
	if s.credentials == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password credential repository is nil", nil)
	}
	if s.hasher == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password hasher is nil", nil)
	}
	if s.box == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password secret box is nil", nil)
	}
	return nil
}

func (s *Service) readyForPasswordWrite() error {
	if err := s.readyForVerify(); err != nil {
		return err
	}
	if s.policy == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "password policy is nil", nil)
	}
	return nil
}

func (s *Service) now() time.Time {
	if s.clock != nil {
		return account.NormalizeTimestamp(s.clock.Now())
	}
	return account.NormalizeTimestamp(time.Now())
}
