package account

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	usernameMinLength = 3
	usernameMaxLength = 32
	displayNameMaxLen = 128

	// RegistrationAcceptedMessage is the only public message returned by the
	// registration service for accepted account creation attempts.
	RegistrationAcceptedMessage = "If the account can be created, check your email."

	// AuditEventRegistrationAttempted is written for registration attempts that
	// pass request validation.
	AuditEventRegistrationAttempted = "account.registration.attempted"
)

var (
	usernamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{1,30}[a-z0-9])$`)

	// ErrInvalidRegistration means the registration request failed local
	// validation before touching storage.
	ErrInvalidRegistration = errors.New("account: invalid registration")
	// ErrRegistrationIdentityTaken lets stores report a duplicate username or
	// email without exposing which field collided.
	ErrRegistrationIdentityTaken = errors.New("account: registration identity already exists")
)

// RegistrationRequest contains the user-provided account registration data.
type RegistrationRequest struct {
	Username        string
	Email           string
	DisplayName     string
	EmailVerified   bool
	EmailVerifiedAt time.Time
	RequestID       string
	IP              string
	UserAgent       string
}

// RegistrationResult is safe to translate directly into a public response.
type RegistrationResult struct {
	Accepted      bool
	PublicMessage string
}

// RegistrationFieldError describes one invalid registration field.
type RegistrationFieldError struct {
	Field  string
	Reason string
}

// RegistrationValidationError contains field-level validation failures.
type RegistrationValidationError struct {
	Fields []RegistrationFieldError
}

func (e *RegistrationValidationError) Error() string {
	if e == nil || len(e.Fields) == 0 {
		return ErrInvalidRegistration.Error()
	}
	return fmt.Sprintf("%s: %s", ErrInvalidRegistration, e.Fields[0].Field)
}

// Unwrap lets errors.Is match ErrInvalidRegistration.
func (e *RegistrationValidationError) Unwrap() error {
	return ErrInvalidRegistration
}

// AccountRegistrationDraft is the normalized account and primary email record
// the registration store must persist atomically.
type AccountRegistrationDraft struct {
	AccountID           AccountID
	EmailID             uuid.UUID
	Username            string
	UsernameNormalized  string
	DisplayName         string
	EmailAddress        string
	EmailNormalized     string
	EmailVerified       bool
	EmailVerifiedAt     time.Time
	AccountMetadataJSON []byte
}

// RegisteredAccount is the account and primary email created by a registration
// store.
type RegisteredAccount struct {
	ID                 AccountID
	EmailID            uuid.UUID
	Username           string
	UsernameNormalized string
	DisplayName        string
	EmailAddress       string
	EmailNormalized    string
	EmailVerified      bool
	EmailVerifiedAt    time.Time
	CreatedAt          time.Time
}

// RegistrationStore owns the storage checks and atomic account/email create.
type RegistrationStore interface {
	UsernameExists(context.Context, string) (bool, error)
	EmailExists(context.Context, string) (bool, error)
	CreateRegistration(context.Context, AccountRegistrationDraft) (RegisteredAccount, error)
}

// RegistrationAuditEvent is a security audit event for account registration.
type RegistrationAuditEvent struct {
	Type       string
	AccountID  AccountID
	RequestID  string
	IP         string
	UserAgent  string
	OccurredAt time.Time
	Attributes map[string]string
}

// RegistrationAuditWriter records registration audit events.
type RegistrationAuditWriter interface {
	WriteRegistrationAuditEvent(context.Context, RegistrationAuditEvent) error
}

// RegistrationIDGenerator creates IDs needed for registration.
type RegistrationIDGenerator interface {
	NewAccountID() (AccountID, error)
	NewEmailID() (uuid.UUID, error)
}

// RegistrationClock returns the current time for deterministic tests.
type RegistrationClock interface {
	Now() time.Time
}

// RegistrationDeps holds the collaborators used by RegistrationService.
type RegistrationDeps struct {
	Store RegistrationStore
	Audit RegistrationAuditWriter
	IDs   RegistrationIDGenerator
	Clock RegistrationClock
}

// RegistrationService creates accounts while preserving the public
// anti-enumeration contract for duplicate usernames and emails.
type RegistrationService struct {
	store RegistrationStore
	audit RegistrationAuditWriter
	ids   RegistrationIDGenerator
	clock RegistrationClock
}

// NewRegistrationService builds an account registration service.
func NewRegistrationService(deps RegistrationDeps) *RegistrationService {
	ids := deps.IDs
	if ids == nil {
		ids = UUIDRegistrationIDGenerator{}
	}
	clock := deps.Clock
	if clock == nil {
		clock = systemRegistrationClock{}
	}
	return &RegistrationService{
		store: deps.Store,
		audit: deps.Audit,
		ids:   ids,
		clock: clock,
	}
}

// Register validates and stores an account registration attempt. Duplicate
// usernames and emails return the same accepted result as a new account.
func (s *RegistrationService) Register(ctx context.Context, req RegistrationRequest) (RegistrationResult, error) {
	if err := s.ready(); err != nil {
		return RegistrationResult{}, err
	}

	normalized, err := normalizeRegistration(req)
	if err != nil {
		return RegistrationResult{}, err
	}

	usernameTaken, err := s.store.UsernameExists(ctx, normalized.UsernameNormalized)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("account: check username availability: %w", err)
	}
	emailTaken, err := s.store.EmailExists(ctx, normalized.EmailNormalized)
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("account: check email availability: %w", err)
	}
	if usernameTaken || emailTaken {
		if err := s.writeAudit(ctx, req, AccountID(uuid.Nil), "accepted_existing", duplicateReason(usernameTaken, emailTaken), normalized.EmailVerified); err != nil {
			return RegistrationResult{}, err
		}
		return acceptedRegistration(), nil
	}

	accountID, err := s.ids.NewAccountID()
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("account: generate account id: %w", err)
	}
	emailID, err := s.ids.NewEmailID()
	if err != nil {
		return RegistrationResult{}, fmt.Errorf("account: generate email id: %w", err)
	}

	now := NormalizeTimestamp(s.clock.Now())
	verifiedAt := NormalizeTimestamp(normalized.EmailVerifiedAt)
	if normalized.EmailVerified && verifiedAt.IsZero() {
		verifiedAt = now
	}
	if !normalized.EmailVerified {
		verifiedAt = time.Time{}
	}

	created, err := s.store.CreateRegistration(ctx, AccountRegistrationDraft{
		AccountID:           accountID,
		EmailID:             emailID,
		Username:            normalized.Username,
		UsernameNormalized:  normalized.UsernameNormalized,
		DisplayName:         normalized.DisplayName,
		EmailAddress:        normalized.EmailAddress,
		EmailNormalized:     normalized.EmailNormalized,
		EmailVerified:       normalized.EmailVerified,
		EmailVerifiedAt:     verifiedAt,
		AccountMetadataJSON: []byte(`{}`),
	})
	if err != nil {
		if errors.Is(err, ErrRegistrationIdentityTaken) {
			if auditErr := s.writeAudit(ctx, req, AccountID(uuid.Nil), "accepted_existing", "duplicate_identity", normalized.EmailVerified); auditErr != nil {
				return RegistrationResult{}, auditErr
			}
			return acceptedRegistration(), nil
		}
		return RegistrationResult{}, fmt.Errorf("account: create registration: %w", err)
	}

	if err := s.writeAudit(ctx, req, created.ID, "created", "created", created.EmailVerified); err != nil {
		return RegistrationResult{}, err
	}
	return acceptedRegistration(), nil
}

func (s *RegistrationService) ready() error {
	if s == nil {
		return errors.New("account: registration service is nil")
	}
	if s.store == nil {
		return errors.New("account: registration store is nil")
	}
	if s.audit == nil {
		return errors.New("account: registration audit writer is nil")
	}
	if s.ids == nil {
		return errors.New("account: registration id generator is nil")
	}
	if s.clock == nil {
		return errors.New("account: registration clock is nil")
	}
	return nil
}

func (s *RegistrationService) writeAudit(ctx context.Context, req RegistrationRequest, accountID AccountID, outcome, reason string, emailVerified bool) error {
	eventType := AuditEventRegistrationAttempted
	return s.audit.WriteRegistrationAuditEvent(ctx, RegistrationAuditEvent{
		Type:       eventType,
		AccountID:  accountID,
		RequestID:  req.RequestID,
		IP:         req.IP,
		UserAgent:  req.UserAgent,
		OccurredAt: NormalizeTimestamp(s.clock.Now()),
		Attributes: map[string]string{
			"outcome":        outcome,
			"reason":         reason,
			"email_verified": strconv.FormatBool(emailVerified),
		},
	})
}

func acceptedRegistration() RegistrationResult {
	return RegistrationResult{
		Accepted:      true,
		PublicMessage: RegistrationAcceptedMessage,
	}
}

type normalizedRegistration struct {
	Username           string
	UsernameNormalized string
	DisplayName        string
	EmailAddress       string
	EmailNormalized    string
	EmailVerified      bool
	EmailVerifiedAt    time.Time
}

func normalizeRegistration(req RegistrationRequest) (normalizedRegistration, error) {
	username, usernameNormalized, usernameErr := normalizeUsernamePair(req.Username)
	emailAddress, emailNormalized, emailErr := normalizeEmailPair(req.Email)
	displayName := strings.TrimSpace(req.DisplayName)

	var fields []RegistrationFieldError
	if usernameErr != nil {
		fields = append(fields, RegistrationFieldError{Field: "username", Reason: usernameErr.Error()})
	}
	if emailErr != nil {
		fields = append(fields, RegistrationFieldError{Field: "email", Reason: emailErr.Error()})
	}
	if len(displayName) > displayNameMaxLen {
		fields = append(fields, RegistrationFieldError{Field: "display_name", Reason: "must be 128 characters or fewer"})
	}
	if len(fields) > 0 {
		return normalizedRegistration{}, &RegistrationValidationError{Fields: fields}
	}
	if displayName == "" {
		displayName = username
	}

	return normalizedRegistration{
		Username:           username,
		UsernameNormalized: usernameNormalized,
		DisplayName:        displayName,
		EmailAddress:       emailAddress,
		EmailNormalized:    emailNormalized,
		EmailVerified:      req.EmailVerified,
		EmailVerifiedAt:    req.EmailVerifiedAt,
	}, nil
}

// NormalizeUsername returns the case-folded username used for uniqueness
// checks.
func NormalizeUsername(value string) (string, error) {
	_, normalized, err := normalizeUsernamePair(value)
	return normalized, err
}

func normalizeUsernamePair(value string) (string, string, error) {
	username := strings.TrimSpace(value)
	if username == "" {
		return "", "", errors.New("is required")
	}
	normalized := strings.ToLower(username)
	if len(normalized) < usernameMinLength || len(normalized) > usernameMaxLength {
		return "", "", fmt.Errorf("must be between %d and %d characters", usernameMinLength, usernameMaxLength)
	}
	if !usernamePattern.MatchString(normalized) {
		return "", "", errors.New("may contain lowercase letters, numbers, underscores, and hyphens, and must start and end with a letter or number")
	}
	return username, normalized, nil
}

// NormalizeEmail returns the case-folded email address used for uniqueness
// checks.
func NormalizeEmail(value string) (string, error) {
	_, normalized, err := normalizeEmailPair(value)
	return normalized, err
}

func normalizeEmailPair(value string) (string, string, error) {
	email := strings.TrimSpace(value)
	if email == "" {
		return "", "", errors.New("is required")
	}
	if strings.ContainsAny(email, "\r\n") {
		return "", "", errors.New("must be a single email address")
	}
	normalized := strings.ToLower(email)
	parsed, err := mail.ParseAddress(normalized)
	if err != nil || parsed.Name != "" || parsed.Address != normalized {
		return "", "", errors.New("must be a valid email address")
	}
	return email, normalized, nil
}

func duplicateReason(usernameTaken, emailTaken bool) string {
	switch {
	case usernameTaken && emailTaken:
		return "duplicate_username_email"
	case usernameTaken:
		return "duplicate_username"
	default:
		return "duplicate_email"
	}
}

// UUIDRegistrationIDGenerator creates UUIDv7 IDs for registration.
type UUIDRegistrationIDGenerator struct{}

// NewAccountID returns a new UUIDv7 account ID.
func (UUIDRegistrationIDGenerator) NewAccountID() (AccountID, error) {
	return NewAccountID()
}

// NewEmailID returns a new UUIDv7 email row ID.
func (UUIDRegistrationIDGenerator) NewEmailID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("account: generate email id: %w", err)
	}
	return id, nil
}

type systemRegistrationClock struct{}

func (systemRegistrationClock) Now() time.Time {
	return time.Now()
}
