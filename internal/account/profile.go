package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const profileMetadataMaxBytes = 16 * 1024

var (
	// ErrInvalidProfile means a profile read or update request is malformed.
	ErrInvalidProfile = errors.New("account: invalid profile")
	// ErrProfileNotFound means the authenticated account no longer exists.
	ErrProfileNotFound = errors.New("account: profile not found")
)

// AccountProfile is the self-service profile view for an authenticated
// account. Metadata is caller-controlled JSON and must not hold secrets.
type AccountProfile struct {
	ID          AccountID
	Username    string
	DisplayName string
	Metadata    json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UpdateProfileRequest contains a partial profile update.
type UpdateProfileRequest struct {
	AccountID      AccountID
	DisplayName    string
	DisplayNameSet bool
	Metadata       json.RawMessage
	MetadataSet    bool
}

// ProfileUpdate is the normalized update sent to storage.
type ProfileUpdate struct {
	AccountID   AccountID
	DisplayName *string
	Metadata    json.RawMessage
	MetadataSet bool
}

// ProfileFieldError describes one invalid profile field.
type ProfileFieldError struct {
	Field  string
	Reason string
}

// ProfileValidationError contains field-level profile validation failures.
type ProfileValidationError struct {
	Fields []ProfileFieldError
}

func (e *ProfileValidationError) Error() string {
	if e == nil || len(e.Fields) == 0 {
		return ErrInvalidProfile.Error()
	}
	return fmt.Sprintf("%s: %s", ErrInvalidProfile, e.Fields[0].Field)
}

// Unwrap lets errors.Is match ErrInvalidProfile.
func (e *ProfileValidationError) Unwrap() error {
	return ErrInvalidProfile
}

// ProfileStore persists account profile settings.
type ProfileStore interface {
	GetProfile(context.Context, AccountID) (AccountProfile, error)
	UpdateProfile(context.Context, ProfileUpdate) (AccountProfile, error)
}

// ProfileDeps holds collaborators for ProfileService.
type ProfileDeps struct {
	Store ProfileStore
}

// ProfileService owns self-service profile reads and updates.
type ProfileService struct {
	store ProfileStore
}

// NewProfileService builds a profile service.
func NewProfileService(deps ProfileDeps) *ProfileService {
	return &ProfileService{store: deps.Store}
}

// GetProfile returns the authenticated account's profile.
func (s *ProfileService) GetProfile(ctx context.Context, accountID AccountID) (AccountProfile, error) {
	if err := s.ready(); err != nil {
		return AccountProfile{}, err
	}
	if accountID.IsZero() {
		return AccountProfile{}, ErrInvalidProfile
	}
	return s.store.GetProfile(ctx, accountID)
}

// UpdateProfile validates and stores a partial profile update.
func (s *ProfileService) UpdateProfile(ctx context.Context, req UpdateProfileRequest) (AccountProfile, error) {
	if err := s.ready(); err != nil {
		return AccountProfile{}, err
	}
	update, err := normalizeProfileUpdate(req)
	if err != nil {
		return AccountProfile{}, err
	}
	return s.store.UpdateProfile(ctx, update)
}

func (s *ProfileService) ready() error {
	if s == nil {
		return errors.New("account: profile service is nil")
	}
	if s.store == nil {
		return errors.New("account: profile store is nil")
	}
	return nil
}

func normalizeProfileUpdate(req UpdateProfileRequest) (ProfileUpdate, error) {
	var fields []ProfileFieldError
	if req.AccountID.IsZero() {
		fields = append(fields, ProfileFieldError{Field: "account_id", Reason: "is required"})
	}
	if !req.DisplayNameSet && !req.MetadataSet {
		fields = append(fields, ProfileFieldError{Field: "profile", Reason: "must include display_name or metadata"})
	}

	var displayName *string
	if req.DisplayNameSet {
		trimmed := strings.TrimSpace(req.DisplayName)
		if len(trimmed) > displayNameMaxLen {
			fields = append(fields, ProfileFieldError{Field: "display_name", Reason: "must be 128 characters or fewer"})
		}
		displayName = &trimmed
	}

	var metadata json.RawMessage
	if req.MetadataSet {
		var metadataFields []ProfileFieldError
		metadata, metadataFields = normalizeProfileMetadata(req.Metadata)
		fields = append(fields, metadataFields...)
	}

	if len(fields) > 0 {
		return ProfileUpdate{}, &ProfileValidationError{Fields: fields}
	}
	return ProfileUpdate{
		AccountID:   req.AccountID,
		DisplayName: displayName,
		Metadata:    metadata,
		MetadataSet: req.MetadataSet,
	}, nil
}

func normalizeProfileMetadata(raw json.RawMessage) (json.RawMessage, []ProfileFieldError) {
	if len(raw) == 0 {
		return nil, []ProfileFieldError{{Field: "metadata", Reason: "is required"}}
	}
	if len(raw) > profileMetadataMaxBytes {
		return nil, []ProfileFieldError{{Field: "metadata", Reason: "must be 16 KiB or smaller"}}
	}

	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, []ProfileFieldError{{Field: "metadata", Reason: "must be a JSON object"}}
	}
	compact, err := json.Marshal(object)
	if err != nil {
		return nil, []ProfileFieldError{{Field: "metadata", Reason: "must be a JSON object"}}
	}
	return append(json.RawMessage(nil), compact...), nil
}
