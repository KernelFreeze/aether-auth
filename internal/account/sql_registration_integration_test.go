//go:build integration

package account

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/KernelFreeze/aether-auth/internal/testutil"
)

func TestSQLRegistrationStoreDuplicateUsernameAndEmail(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewPostgresDB(t)
	store := NewSQLRegistrationStore(db.Pool)

	first := registrationDraft(t,
		"018f1f74-10a1-7000-9000-000000000701",
		"018f1f74-10a1-7000-9000-000000000702",
		"celeste",
		"celeste@example.com",
	)
	if _, err := store.CreateRegistration(ctx, first); err != nil {
		t.Fatalf("create first registration: %v", err)
	}

	if ok, err := store.UsernameExists(ctx, "celeste"); err != nil || !ok {
		t.Fatalf("UsernameExists() = %t, %v; want true, nil", ok, err)
	}
	if ok, err := store.EmailExists(ctx, "celeste@example.com"); err != nil || !ok {
		t.Fatalf("EmailExists() = %t, %v; want true, nil", ok, err)
	}

	tests := []struct {
		name  string
		draft AccountRegistrationDraft
	}{
		{
			name: "duplicate username",
			draft: registrationDraft(t,
				"018f1f74-10a1-7000-9000-000000000703",
				"018f1f74-10a1-7000-9000-000000000704",
				"celeste",
				"other@example.com",
			),
		},
		{
			name: "duplicate email",
			draft: registrationDraft(t,
				"018f1f74-10a1-7000-9000-000000000705",
				"018f1f74-10a1-7000-9000-000000000706",
				"other",
				"celeste@example.com",
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.CreateRegistration(ctx, tt.draft)
			if !errors.Is(err, ErrRegistrationIdentityTaken) {
				t.Fatalf("create registration error = %v, want ErrRegistrationIdentityTaken", err)
			}
		})
	}
}

func registrationDraft(t testing.TB, accountIDValue, emailIDValue, username, email string) AccountRegistrationDraft {
	t.Helper()

	accountID, err := ParseAccountID(accountIDValue)
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	emailID := uuid.MustParse(emailIDValue)
	return AccountRegistrationDraft{
		AccountID:           accountID,
		EmailID:             emailID,
		Username:            username,
		UsernameNormalized:  username,
		DisplayName:         username,
		EmailAddress:        email,
		EmailNormalized:     email,
		AccountMetadataJSON: []byte(`{}`),
	}
}
