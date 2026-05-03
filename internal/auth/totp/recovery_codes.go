package totp

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	platformcrypto "github.com/KernelFreeze/aether-auth/internal/platform/crypto"
)

// RecoveryCodeRecord is a stored recovery code hash.
type RecoveryCodeRecord struct {
	ID           uuid.UUID
	AccountID    account.AccountID
	CredentialID account.CredentialID
	CodeHash     []byte
	UsedAt       time.Time
	CreatedAt    time.Time
}

// RecoveryCodeSet contains replacement hashes for a recovery-code credential.
type RecoveryCodeSet struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	CodeHashes   [][]byte
}

// RecoveryCodeConsumption identifies a single-use recovery code to consume.
type RecoveryCodeConsumption struct {
	ID           uuid.UUID
	AccountID    account.AccountID
	CredentialID account.CredentialID
	UsedAt       time.Time
}

// RecoveryCodeStore persists recovery-code hashes.
type RecoveryCodeStore interface {
	ReplaceRecoveryCodes(context.Context, RecoveryCodeSet) ([]RecoveryCodeRecord, error)
	ListUnusedRecoveryCodes(context.Context, account.AccountID, account.CredentialID) ([]RecoveryCodeRecord, error)
	ConsumeRecoveryCode(context.Context, RecoveryCodeConsumption) (RecoveryCodeRecord, error)
}

// GenerateRecoveryCodes creates a fresh recovery-code credential if needed,
// replaces unused code hashes, and returns the raw one-time codes.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, req GenerateRecoveryCodesRequest) (GeneratedRecoveryCodes, error) {
	if err := s.readyForRecoveryCodes(); err != nil {
		return GeneratedRecoveryCodes{}, err
	}
	if req.AccountID.IsZero() {
		return GeneratedRecoveryCodes{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}

	credential, err := s.recoveryCodeCredential(ctx, req.AccountID, req.CredentialID, true)
	if err != nil {
		return GeneratedRecoveryCodes{}, err
	}
	count := req.Count
	if count <= 0 {
		count = s.recoveryCodeCount()
	}
	length := req.Length
	if length <= 0 {
		length = s.recoveryCodeLength()
	}

	rawCodes := make([]string, count)
	hashes := make([][]byte, count)
	for i := range rawCodes {
		raw, err := platformcrypto.RandomStringFrom(s.randomReader(), length, s.recoveryCodeAlphabet())
		if err != nil {
			return GeneratedRecoveryCodes{}, fmt.Errorf("totp: generate recovery code: %w", err)
		}
		raw = normalizeRecoveryCode(raw)
		hash, err := s.hasher.HashPassword(ctx, auth.PasswordHashRequest{
			Password:  raw,
			AccountID: req.AccountID,
		})
		if err != nil {
			return GeneratedRecoveryCodes{}, fmt.Errorf("totp: hash recovery code: %w", err)
		}
		rawCodes[i] = raw
		hashes[i] = []byte(hash.PHCString)
	}

	records, err := s.recoveryCodes.ReplaceRecoveryCodes(ctx, RecoveryCodeSet{
		AccountID:    req.AccountID,
		CredentialID: credential.ID,
		CodeHashes:   hashes,
	})
	if err != nil {
		return GeneratedRecoveryCodes{}, err
	}
	return GeneratedRecoveryCodes{
		AccountID:    req.AccountID,
		CredentialID: credential.ID,
		Codes:        rawCodes,
		Records:      records,
	}, nil
}

// VerifyRecoveryCode consumes one valid recovery code and returns its factor
// check. Replays fail because consumed records are no longer listed.
func (s *Service) VerifyRecoveryCode(ctx context.Context, req VerifyRecoveryCodeRequest) (auth.FactorCheck, auth.CredentialSnapshot, error) {
	if err := s.readyForRecoveryCodes(); err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}
	if req.AccountID.IsZero() {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "account id is required", nil)
	}
	code := normalizeRecoveryCode(req.Code)
	if code == "" {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "recovery code is required", nil)
	}

	credential, err := s.recoveryCodeCredential(ctx, req.AccountID, req.CredentialID, false)
	if err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}
	records, err := s.recoveryCodes.ListUnusedRecoveryCodes(ctx, req.AccountID, credential.ID)
	if err != nil {
		return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
	}

	now := s.now()
	for _, record := range records {
		result, err := s.hasher.VerifyPassword(ctx, auth.PasswordVerifyRequest{
			Password:  code,
			Hash:      auth.PasswordHash{PHCString: string(record.CodeHash)},
			AccountID: req.AccountID,
		})
		if err != nil {
			return auth.FactorCheck{}, auth.CredentialSnapshot{}, fmt.Errorf("totp: verify recovery code: %w", err)
		}
		if !result.Matched {
			continue
		}
		if _, err := s.recoveryCodes.ConsumeRecoveryCode(ctx, RecoveryCodeConsumption{
			ID:           record.ID,
			AccountID:    req.AccountID,
			CredentialID: credential.ID,
			UsedAt:       now,
		}); err != nil {
			return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
		}
		if _, err := s.credentials.UpdateCredential(ctx, auth.CredentialUpdate{
			CredentialID: credential.ID,
			LastUsedAt:   now,
		}); err != nil {
			return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
		}
		if err := s.recordSuccess(ctx, AttemptSuccess{
			AccountID:    req.AccountID,
			CredentialID: credential.ID,
			Factor:       account.FactorKindRecoveryCode,
			IP:           req.IP,
			UserAgent:    req.UserAgent,
			OccurredAt:   now,
			Endpoint:     req.Endpoint,
		}); err != nil {
			return auth.FactorCheck{}, auth.CredentialSnapshot{}, err
		}
		return auth.FactorCheck{
			Kind:             account.FactorKindRecoveryCode,
			VerifiedAt:       now,
			ChallengeBinding: req.ChallengeBinding,
		}, credential, nil
	}

	return auth.FactorCheck{}, auth.CredentialSnapshot{}, s.recordFailure(ctx, AttemptFailure{
		AccountID:    req.AccountID,
		CredentialID: credential.ID,
		Factor:       account.FactorKindRecoveryCode,
		IP:           req.IP,
		UserAgent:    req.UserAgent,
		OccurredAt:   now,
		Endpoint:     req.Endpoint,
	})
}

func (s *Service) recoveryCodeCredential(ctx context.Context, accountID account.AccountID, credentialID account.CredentialID, create bool) (auth.CredentialSnapshot, error) {
	if !credentialID.IsZero() {
		credential, err := s.credentials.LookupCredential(ctx, auth.CredentialLookup{CredentialID: credentialID})
		if err != nil {
			return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
		}
		if credential.AccountID != accountID || credential.Kind != account.CredentialKindRecoveryCode || !credential.Verified {
			return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
		}
		return credential, nil
	}

	credential, err := s.credentials.LookupCredential(ctx, auth.CredentialLookup{
		AccountID: accountID,
		Kind:      account.CredentialKindRecoveryCode,
	})
	if err == nil {
		if !credential.Verified {
			return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
		}
		return credential, nil
	}
	if !create {
		return auth.CredentialSnapshot{}, auth.ErrInvalidCredentials
	}

	return s.credentials.CreateCredential(ctx, auth.CredentialDraft{
		AccountID: accountID,
		Kind:      account.CredentialKindRecoveryCode,
		Verified:  true,
	})
}

func (s *Service) readyForRecoveryCodes() error {
	if s == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "totp service is nil", nil)
	}
	if s.credentials == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "recovery-code credential repository is nil", nil)
	}
	if s.recoveryCodes == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "recovery-code store is nil", nil)
	}
	if s.hasher == nil {
		return auth.NewServiceError(auth.ErrorKindInternal, "recovery-code hasher is nil", nil)
	}
	return nil
}

func normalizeRecoveryCode(code string) string {
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return strings.ToUpper(code)
}

// GenerateRecoveryCodesRequest describes recovery-code generation.
type GenerateRecoveryCodesRequest struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Count        int
	Length       int
}

// GeneratedRecoveryCodes contains raw codes returned once to the client.
type GeneratedRecoveryCodes struct {
	AccountID    account.AccountID
	CredentialID account.CredentialID
	Codes        []string
	Records      []RecoveryCodeRecord
}

// VerifyRecoveryCodeRequest verifies one recovery code during MFA.
type VerifyRecoveryCodeRequest struct {
	AccountID        account.AccountID
	CredentialID     account.CredentialID
	Code             string
	IP               netip.Addr
	UserAgent        string
	Endpoint         string
	ChallengeBinding string
}
