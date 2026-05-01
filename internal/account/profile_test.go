package account

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestProfileServiceUpdatesDisplayNameAndMetadata(t *testing.T) {
	ctx := context.Background()
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000401")
	store := &fakeProfileStore{}
	service := NewProfileService(ProfileDeps{Store: store})

	got, err := service.UpdateProfile(ctx, UpdateProfileRequest{
		AccountID:      accountID,
		DisplayName:    "  Celeste Love  ",
		DisplayNameSet: true,
		Metadata:       json.RawMessage(`{"locale":"en-US","timezone":"America/Bogota"}`),
		MetadataSet:    true,
	})
	if err != nil {
		t.Fatalf("update profile: %v", err)
	}

	if store.update.AccountID != accountID {
		t.Fatalf("update account id = %s, want %s", store.update.AccountID, accountID)
	}
	if store.update.DisplayName == nil || *store.update.DisplayName != "Celeste Love" {
		t.Fatalf("display name update = %#v", store.update.DisplayName)
	}
	var metadata map[string]string
	if err := json.Unmarshal(store.update.Metadata, &metadata); err != nil {
		t.Fatalf("decode metadata update: %v", err)
	}
	if metadata["locale"] != "en-US" || metadata["timezone"] != "America/Bogota" {
		t.Fatalf("metadata update = %#v", metadata)
	}
	if got.ID != accountID || got.DisplayName != "Celeste Love" {
		t.Fatalf("profile = %#v", got)
	}
}

func TestProfileServiceRejectsInvalidUpdates(t *testing.T) {
	accountID := mustCredentialAccountID(t, "018f1f74-10a1-7000-9000-000000000402")
	service := NewProfileService(ProfileDeps{Store: &fakeProfileStore{}})

	tests := []struct {
		name string
		req  UpdateProfileRequest
	}{
		{
			name: "no fields",
			req:  UpdateProfileRequest{AccountID: accountID},
		},
		{
			name: "long display name",
			req: UpdateProfileRequest{
				AccountID:      accountID,
				DisplayName:    stringsOfLength(displayNameMaxLen + 1),
				DisplayNameSet: true,
			},
		},
		{
			name: "metadata array",
			req: UpdateProfileRequest{
				AccountID:   accountID,
				Metadata:    json.RawMessage(`["not","an","object"]`),
				MetadataSet: true,
			},
		},
		{
			name: "zero account id",
			req: UpdateProfileRequest{
				DisplayName:    "Celeste",
				DisplayNameSet: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.UpdateProfile(context.Background(), tt.req)
			if !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("update error = %v, want ErrInvalidProfile", err)
			}
		})
	}
}

type fakeProfileStore struct {
	profile AccountProfile
	update  ProfileUpdate
	err     error
}

func (s *fakeProfileStore) GetProfile(context.Context, AccountID) (AccountProfile, error) {
	if s.err != nil {
		return AccountProfile{}, s.err
	}
	return s.profile, nil
}

func (s *fakeProfileStore) UpdateProfile(_ context.Context, update ProfileUpdate) (AccountProfile, error) {
	s.update = update
	if s.err != nil {
		return AccountProfile{}, s.err
	}
	displayName := ""
	if update.DisplayName != nil {
		displayName = *update.DisplayName
	}
	return AccountProfile{
		ID:          update.AccountID,
		Username:    "celeste",
		DisplayName: displayName,
		Metadata:    update.Metadata,
		UpdatedAt:   time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
	}, nil
}
