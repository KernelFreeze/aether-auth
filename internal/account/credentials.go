package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultCredentialReauthWindow = 5 * time.Minute
	credentialPayloadAlgorithm    = "aes-256-gcm"
	credentialPayloadVersion      = int32(1)
)

var (
	// ErrInvalidCredential means a credential management request is malformed.
	ErrInvalidCredential = errors.New("account: invalid credential")
	// ErrCredentialNotFound means no active credential matched the request.
	ErrCredentialNotFound = errors.New("account: credential not found")
	// ErrCredentialAlreadyExists means an OIDC provider subject is already linked.
	ErrCredentialAlreadyExists = errors.New("account: credential already exists")
	// ErrLastCredential means removing a credential would leave the account unusable.
	ErrLastCredential = errors.New("account: last credential cannot be removed")
	// ErrCredentialReauthenticationRequired means a destructive credential change
	// needs a recent primary authentication proof.
	ErrCredentialReauthenticationRequired = errors.New("account: credential change requires recent reauthentication")
)

// Credential is an internal account credential record. Payload is encrypted
// storage data and must not be returned directly from HTTP handlers.
type Credential struct {
	ID              CredentialID
	AccountID       AccountID
	Kind            CredentialKind
	Provider        string
	ExternalSubject string
	DisplayName     string
	Verified        bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastUsedAt      time.Time
	RevokedAt       time.Time
	Payload         CredentialPayload
}

// CredentialPayload is encrypted credential data and the metadata needed to
// decrypt it later.
type CredentialPayload struct {
	Algorithm  string
	KeyRef     string
	Nonce      []byte
	Ciphertext []byte
	AAD        []byte
	Version    int32
}

// Empty reports whether no encrypted payload is present.
func (p CredentialPayload) Empty() bool {
	return len(p.Ciphertext) == 0
}

// CredentialWithPayload includes decrypted JSON payload data. It is for
// service-internal use only; handlers should map credentials to public views.
type CredentialWithPayload struct {
	Credential
	PayloadJSON json.RawMessage
}

// CreateCredentialRequest contains the generic fields used by all credential
// kinds.
type CreateCredentialRequest struct {
	AccountID       AccountID
	Kind            CredentialKind
	Provider        string
	ExternalSubject string
	DisplayName     string
	Verified        bool
	Payload         any
}

// UpdateCredentialRequest contains mutable credential fields. Payload changes
// require recent reauthentication because they replace verifier material.
type UpdateCredentialRequest struct {
	AccountID         AccountID
	CredentialID      CredentialID
	Verified          *bool
	LastUsedAt        time.Time
	Payload           any
	PayloadSet        bool
	ReauthenticatedAt time.Time
}

// RemoveCredentialRequest describes a credential removal attempt.
type RemoveCredentialRequest struct {
	AccountID         AccountID
	CredentialID      CredentialID
	ReauthenticatedAt time.Time
}

// CredentialDraft is the store-ready credential data.
type CredentialDraft struct {
	ID              CredentialID
	AccountID       AccountID
	Kind            CredentialKind
	Provider        string
	ExternalSubject string
	DisplayName     string
	Verified        bool
	Payload         CredentialPayload
}

// CredentialUpdate is the store-ready credential update.
type CredentialUpdate struct {
	AccountID    AccountID
	CredentialID CredentialID
	Verified     *bool
	LastUsedAt   time.Time
	Payload      *CredentialPayload
}

// CredentialStore persists and retrieves account credentials.
type CredentialStore interface {
	ProviderSubjectExists(context.Context, string, string) (bool, error)
	CreateCredential(context.Context, CredentialDraft) (Credential, error)
	GetCredential(context.Context, AccountID, CredentialID) (Credential, error)
	ListCredentials(context.Context, AccountID) ([]Credential, error)
	UpdateCredential(context.Context, CredentialUpdate) (Credential, error)
	RemoveCredential(context.Context, AccountID, CredentialID, time.Time) (Credential, error)
}

// CredentialPayloadSealRequest is sent to the encryption boundary.
type CredentialPayloadSealRequest struct {
	Plaintext      []byte
	AssociatedData []byte
}

// CredentialPayloadOpenRequest is sent to the decryption boundary.
type CredentialPayloadOpenRequest struct {
	Payload        CredentialPayload
	AssociatedData []byte
}

// CredentialPayloadBox encrypts and decrypts credential payload JSON.
type CredentialPayloadBox interface {
	SealCredentialPayload(context.Context, CredentialPayloadSealRequest) (CredentialPayload, error)
	OpenCredentialPayload(context.Context, CredentialPayloadOpenRequest) ([]byte, error)
}

// CredentialIDGenerator creates credential IDs.
type CredentialIDGenerator interface {
	NewCredentialID() (CredentialID, error)
}

// CredentialClock returns the current time for reauthentication windows.
type CredentialClock interface {
	Now() time.Time
}

// CredentialDeps holds collaborators for CredentialService.
type CredentialDeps struct {
	Store        CredentialStore
	Box          CredentialPayloadBox
	IDs          CredentialIDGenerator
	Clock        CredentialClock
	ReauthWindow time.Duration
}

// CredentialService owns credential creation, payload encryption, and removal
// policy checks.
type CredentialService struct {
	store        CredentialStore
	box          CredentialPayloadBox
	ids          CredentialIDGenerator
	clock        CredentialClock
	reauthWindow time.Duration
}

// NewCredentialService builds a credential management service.
func NewCredentialService(deps CredentialDeps) *CredentialService {
	ids := deps.IDs
	if ids == nil {
		ids = UUIDCredentialIDGenerator{}
	}
	clock := deps.Clock
	if clock == nil {
		clock = systemRegistrationClock{}
	}
	window := deps.ReauthWindow
	if window <= 0 {
		window = defaultCredentialReauthWindow
	}
	return &CredentialService{
		store:        deps.Store,
		box:          deps.Box,
		ids:          ids,
		clock:        clock,
		reauthWindow: window,
	}
}

// CreateCredential stores a credential and encrypts its JSON payload.
func (s *CredentialService) CreateCredential(ctx context.Context, req CreateCredentialRequest) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	normalized, err := normalizeCredential(req.AccountID, req.Kind, req.Provider, req.ExternalSubject, req.DisplayName)
	if err != nil {
		return Credential{}, err
	}
	if normalized.Kind == CredentialKindOIDC {
		exists, err := s.store.ProviderSubjectExists(ctx, normalized.Provider, normalized.ExternalSubject)
		if err != nil {
			return Credential{}, fmt.Errorf("account: check oidc credential uniqueness: %w", err)
		}
		if exists {
			return Credential{}, ErrCredentialAlreadyExists
		}
	}

	id, err := s.ids.NewCredentialID()
	if err != nil {
		return Credential{}, fmt.Errorf("account: generate credential id: %w", err)
	}

	var payload CredentialPayload
	if req.Payload != nil {
		payload, err = s.sealPayload(ctx, credentialPayloadContext{
			AccountID:       normalized.AccountID,
			CredentialID:    id,
			Kind:            normalized.Kind,
			Provider:        normalized.Provider,
			ExternalSubject: normalized.ExternalSubject,
		}, req.Payload)
		if err != nil {
			return Credential{}, err
		}
	}

	created, err := s.store.CreateCredential(ctx, CredentialDraft{
		ID:              id,
		AccountID:       normalized.AccountID,
		Kind:            normalized.Kind,
		Provider:        normalized.Provider,
		ExternalSubject: normalized.ExternalSubject,
		DisplayName:     normalized.DisplayName,
		Verified:        req.Verified,
		Payload:         payload,
	})
	if err != nil {
		return Credential{}, fmt.Errorf("account: create credential: %w", err)
	}
	return created, nil
}

// GetCredential returns one active credential without decrypting payload data.
func (s *CredentialService) GetCredential(ctx context.Context, accountID AccountID, credentialID CredentialID) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if accountID.IsZero() || credentialID.IsZero() {
		return Credential{}, ErrInvalidCredential
	}
	return s.store.GetCredential(ctx, accountID, credentialID)
}

// ReadCredential returns one active credential with decrypted JSON payload.
func (s *CredentialService) ReadCredential(ctx context.Context, accountID AccountID, credentialID CredentialID) (CredentialWithPayload, error) {
	credential, err := s.GetCredential(ctx, accountID, credentialID)
	if err != nil {
		return CredentialWithPayload{}, err
	}
	payload, err := s.openPayload(ctx, credential)
	if err != nil {
		return CredentialWithPayload{}, err
	}
	return CredentialWithPayload{Credential: credential, PayloadJSON: payload}, nil
}

// ListCredentials returns active credentials for an account without decrypted
// payloads.
func (s *CredentialService) ListCredentials(ctx context.Context, accountID AccountID) ([]Credential, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if accountID.IsZero() {
		return nil, ErrInvalidCredential
	}
	return s.store.ListCredentials(ctx, accountID)
}

// UpdateCredential updates mutable credential state. Replacing payload data
// requires recent reauthentication.
func (s *CredentialService) UpdateCredential(ctx context.Context, req UpdateCredentialRequest) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if req.AccountID.IsZero() || req.CredentialID.IsZero() {
		return Credential{}, ErrInvalidCredential
	}
	if req.Verified == nil && req.LastUsedAt.IsZero() && !req.PayloadSet {
		return Credential{}, ErrInvalidCredential
	}

	var payload *CredentialPayload
	if req.PayloadSet {
		if err := s.requireRecentReauthentication(req.ReauthenticatedAt); err != nil {
			return Credential{}, err
		}
		current, err := s.store.GetCredential(ctx, req.AccountID, req.CredentialID)
		if err != nil {
			return Credential{}, err
		}
		sealed, err := s.sealPayload(ctx, credentialPayloadContext{
			AccountID:       current.AccountID,
			CredentialID:    current.ID,
			Kind:            current.Kind,
			Provider:        current.Provider,
			ExternalSubject: current.ExternalSubject,
		}, req.Payload)
		if err != nil {
			return Credential{}, err
		}
		payload = &sealed
	}

	updated, err := s.store.UpdateCredential(ctx, CredentialUpdate{
		AccountID:    req.AccountID,
		CredentialID: req.CredentialID,
		Verified:     req.Verified,
		LastUsedAt:   NormalizeTimestamp(req.LastUsedAt),
		Payload:      payload,
	})
	if err != nil {
		return Credential{}, fmt.Errorf("account: update credential: %w", err)
	}
	return updated, nil
}

// RemoveCredential revokes one credential after a recent reauthentication
// proof. The store must preserve the last active credential.
func (s *CredentialService) RemoveCredential(ctx context.Context, req RemoveCredentialRequest) (Credential, error) {
	if err := s.ready(); err != nil {
		return Credential{}, err
	}
	if req.AccountID.IsZero() || req.CredentialID.IsZero() {
		return Credential{}, ErrInvalidCredential
	}
	if err := s.requireRecentReauthentication(req.ReauthenticatedAt); err != nil {
		return Credential{}, err
	}

	removed, err := s.store.RemoveCredential(ctx, req.AccountID, req.CredentialID, NormalizeTimestamp(s.clock.Now()))
	if err != nil {
		return Credential{}, fmt.Errorf("account: remove credential: %w", err)
	}
	return removed, nil
}

func (s *CredentialService) ready() error {
	if s == nil {
		return errors.New("account: credential service is nil")
	}
	if s.store == nil {
		return errors.New("account: credential store is nil")
	}
	if s.ids == nil {
		return errors.New("account: credential id generator is nil")
	}
	if s.clock == nil {
		return errors.New("account: credential clock is nil")
	}
	return nil
}

func (s *CredentialService) requireRecentReauthentication(reauthenticatedAt time.Time) error {
	reauthenticatedAt = NormalizeTimestamp(reauthenticatedAt)
	now := NormalizeTimestamp(s.clock.Now())
	if reauthenticatedAt.IsZero() || reauthenticatedAt.After(now) || now.Sub(reauthenticatedAt) > s.reauthWindow {
		return ErrCredentialReauthenticationRequired
	}
	return nil
}

type credentialPayloadContext struct {
	AccountID       AccountID
	CredentialID    CredentialID
	Kind            CredentialKind
	Provider        string
	ExternalSubject string
}

func (s *CredentialService) sealPayload(ctx context.Context, c credentialPayloadContext, payload any) (CredentialPayload, error) {
	if s.box == nil {
		return CredentialPayload{}, errors.New("account: credential payload box is nil")
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return CredentialPayload{}, fmt.Errorf("account: marshal credential payload: %w", err)
	}
	if !json.Valid(plaintext) {
		return CredentialPayload{}, fmt.Errorf("%w: payload must be valid JSON", ErrInvalidCredential)
	}
	aad, err := credentialAssociatedData(c)
	if err != nil {
		return CredentialPayload{}, err
	}
	sealed, err := s.box.SealCredentialPayload(ctx, CredentialPayloadSealRequest{
		Plaintext:      plaintext,
		AssociatedData: aad,
	})
	if err != nil {
		return CredentialPayload{}, fmt.Errorf("account: seal credential payload: %w", err)
	}
	if sealed.Algorithm == "" {
		sealed.Algorithm = credentialPayloadAlgorithm
	}
	if sealed.Version == 0 {
		sealed.Version = credentialPayloadVersion
	}
	sealed.AAD = append([]byte(nil), aad...)
	return sealed, nil
}

func (s *CredentialService) openPayload(ctx context.Context, credential Credential) (json.RawMessage, error) {
	if credential.Payload.Empty() {
		return nil, nil
	}
	if s.box == nil {
		return nil, errors.New("account: credential payload box is nil")
	}
	plaintext, err := s.box.OpenCredentialPayload(ctx, CredentialPayloadOpenRequest{
		Payload:        credential.Payload,
		AssociatedData: credential.Payload.AAD,
	})
	if err != nil {
		return nil, fmt.Errorf("account: open credential payload: %w", err)
	}
	if !json.Valid(plaintext) {
		return nil, fmt.Errorf("%w: stored credential payload is not JSON", ErrInvalidCredential)
	}
	return append(json.RawMessage(nil), plaintext...), nil
}

type normalizedCredential struct {
	AccountID       AccountID
	Kind            CredentialKind
	Provider        string
	ExternalSubject string
	DisplayName     string
}

func normalizeCredential(accountID AccountID, kind CredentialKind, provider, externalSubject, displayName string) (normalizedCredential, error) {
	if accountID.IsZero() || !kind.Valid() {
		return normalizedCredential{}, ErrInvalidCredential
	}
	normalized := normalizedCredential{
		AccountID:       accountID,
		Kind:            kind,
		Provider:        strings.ToLower(strings.TrimSpace(provider)),
		ExternalSubject: strings.TrimSpace(externalSubject),
		DisplayName:     strings.TrimSpace(displayName),
	}
	if len(normalized.DisplayName) > displayNameMaxLen {
		return normalizedCredential{}, fmt.Errorf("%w: display name must be 128 characters or fewer", ErrInvalidCredential)
	}
	if kind == CredentialKindOIDC {
		if normalized.Provider == "" || normalized.ExternalSubject == "" {
			return normalizedCredential{}, fmt.Errorf("%w: oidc credentials require provider and external subject", ErrInvalidCredential)
		}
		return normalized, nil
	}
	if normalized.Provider != "" || normalized.ExternalSubject != "" {
		return normalizedCredential{}, fmt.Errorf("%w: provider fields are only valid for oidc credentials", ErrInvalidCredential)
	}
	return normalized, nil
}

type credentialAAD struct {
	AccountID       string `json:"account_id"`
	CredentialID    string `json:"credential_id"`
	Kind            string `json:"kind"`
	Provider        string `json:"provider,omitempty"`
	ExternalSubject string `json:"external_subject,omitempty"`
}

func credentialAssociatedData(c credentialPayloadContext) ([]byte, error) {
	if c.AccountID.IsZero() || c.CredentialID.IsZero() || !c.Kind.Valid() {
		return nil, ErrInvalidCredential
	}
	aad, err := json.Marshal(credentialAAD{
		AccountID:       c.AccountID.String(),
		CredentialID:    c.CredentialID.String(),
		Kind:            c.Kind.String(),
		Provider:        c.Provider,
		ExternalSubject: c.ExternalSubject,
	})
	if err != nil {
		return nil, fmt.Errorf("account: marshal credential aad: %w", err)
	}
	return aad, nil
}

// UUIDCredentialIDGenerator creates UUIDv7 credential IDs.
type UUIDCredentialIDGenerator struct{}

// NewCredentialID returns a new UUIDv7 credential ID.
func (UUIDCredentialIDGenerator) NewCredentialID() (CredentialID, error) {
	return NewCredentialID()
}
