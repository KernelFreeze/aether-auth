package account

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewIDsReturnUUIDv7(t *testing.T) {
	tests := []struct {
		name string
		new  func() (uuid.UUID, error)
	}{
		{
			name: "account",
			new: func() (uuid.UUID, error) {
				id, err := NewAccountID()
				return id.UUID(), err
			},
		},
		{
			name: "credential",
			new: func() (uuid.UUID, error) {
				id, err := NewCredentialID()
				return id.UUID(), err
			},
		},
		{
			name: "session",
			new: func() (uuid.UUID, error) {
				id, err := NewSessionID()
				return id.UUID(), err
			},
		},
		{
			name: "organization",
			new: func() (uuid.UUID, error) {
				id, err := NewOrganizationID()
				return id.UUID(), err
			},
		},
		{
			name: "client",
			new: func() (uuid.UUID, error) {
				id, err := NewClientID()
				return id.UUID(), err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := tt.new()
			if err != nil {
				t.Fatalf("new id: %v", err)
			}
			if id == uuid.Nil {
				t.Fatal("new id returned nil UUID")
			}
			if got := id.Version(); got != 7 {
				t.Fatalf("UUID version = %d, want 7", got)
			}
		})
	}
}

func TestIDParsingRejectsMalformedAndNilUUIDs(t *testing.T) {
	valid := "018f1f47-4000-7c09-8d93-9f12a5e0a111"

	tests := []struct {
		name  string
		parse func(string) (uuid.UUID, error)
	}{
		{
			name: "account",
			parse: func(value string) (uuid.UUID, error) {
				id, err := ParseAccountID(value)
				return id.UUID(), err
			},
		},
		{
			name: "credential",
			parse: func(value string) (uuid.UUID, error) {
				id, err := ParseCredentialID(value)
				return id.UUID(), err
			},
		},
		{
			name: "session",
			parse: func(value string) (uuid.UUID, error) {
				id, err := ParseSessionID(value)
				return id.UUID(), err
			},
		},
		{
			name: "organization",
			parse: func(value string) (uuid.UUID, error) {
				id, err := ParseOrganizationID(value)
				return id.UUID(), err
			},
		},
		{
			name: "client",
			parse: func(value string) (uuid.UUID, error) {
				id, err := ParseClientID(value)
				return id.UUID(), err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := tt.parse(valid)
			if err != nil {
				t.Fatalf("parse valid ID: %v", err)
			}
			if got := id.String(); got != valid {
				t.Fatalf("parsed ID = %q, want %q", got, valid)
			}

			if _, err := tt.parse("not-a-uuid"); err == nil {
				t.Fatal("parse malformed ID: got nil error")
			}
			if _, err := tt.parse(uuid.Nil.String()); err == nil {
				t.Fatal("parse nil UUID: got nil error")
			}
		})
	}
}

func TestAccountIDTextAndJSONEncoding(t *testing.T) {
	const value = "018f1f47-4000-7c09-8d93-9f12a5e0a111"

	id, err := ParseAccountID(value)
	if err != nil {
		t.Fatalf("parse account ID: %v", err)
	}

	text, err := id.MarshalText()
	if err != nil {
		t.Fatalf("marshal text: %v", err)
	}
	if got := string(text); got != value {
		t.Fatalf("text = %q, want %q", got, value)
	}

	var decoded AccountID
	if err := decoded.UnmarshalText(text); err != nil {
		t.Fatalf("unmarshal text: %v", err)
	}
	if decoded != id {
		t.Fatalf("decoded ID = %v, want %v", decoded, id)
	}

	payload, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	if got, want := string(payload), `"`+value+`"`; got != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
}

func TestCredentialKinds(t *testing.T) {
	want := []CredentialKind{
		CredentialKindPassword,
		CredentialKindWebAuthn,
		CredentialKindOIDC,
		CredentialKindTOTP,
		CredentialKindRecoveryCode,
	}

	got := CredentialKinds()
	if len(got) != len(want) {
		t.Fatalf("CredentialKinds length = %d, want %d", len(got), len(want))
	}
	for i, kind := range got {
		if kind != want[i] {
			t.Fatalf("CredentialKinds[%d] = %q, want %q", i, kind, want[i])
		}
		if !kind.Valid() {
			t.Fatalf("%q should be valid", kind)
		}
		parsed, err := ParseCredentialKind(kind.String())
		if err != nil {
			t.Fatalf("parse %q: %v", kind, err)
		}
		if parsed != kind {
			t.Fatalf("parsed kind = %q, want %q", parsed, kind)
		}
	}

	got[0] = "mutated"
	if CredentialKinds()[0] != CredentialKindPassword {
		t.Fatal("CredentialKinds returned mutable package storage")
	}

	for _, value := range []string{"", "email", "webauthn "} {
		if _, err := ParseCredentialKind(value); err == nil {
			t.Fatalf("ParseCredentialKind(%q): got nil error", value)
		}
	}
}

func TestFactorKinds(t *testing.T) {
	want := []FactorKind{
		FactorKindUser,
		FactorKindPassword,
		FactorKindPasskey,
		FactorKindIDP,
		FactorKindTOTP,
		FactorKindRecoveryCode,
	}

	got := FactorKinds()
	if len(got) != len(want) {
		t.Fatalf("FactorKinds length = %d, want %d", len(got), len(want))
	}
	for i, kind := range got {
		if kind != want[i] {
			t.Fatalf("FactorKinds[%d] = %q, want %q", i, kind, want[i])
		}
		if !kind.Valid() {
			t.Fatalf("%q should be valid", kind)
		}
		parsed, err := ParseFactorKind(kind.String())
		if err != nil {
			t.Fatalf("parse %q: %v", kind, err)
		}
		if parsed != kind {
			t.Fatalf("parsed kind = %q, want %q", parsed, kind)
		}
	}

	got[0] = "mutated"
	if FactorKinds()[0] != FactorKindUser {
		t.Fatal("FactorKinds returned mutable package storage")
	}

	for _, value := range []string{"", "email", "passkey "} {
		if _, err := ParseFactorKind(value); err == nil {
			t.Fatalf("ParseFactorKind(%q): got nil error", value)
		}
	}
}

func TestTimestampConventions(t *testing.T) {
	cot := time.FixedZone("America/Bogota", -5*60*60)
	local := time.Date(2026, 5, 1, 9, 30, 0, 123, cot)

	normalized := NormalizeTimestamp(local)
	if normalized.Location() != time.UTC {
		t.Fatalf("location = %v, want UTC", normalized.Location())
	}
	if !normalized.Equal(local) {
		t.Fatalf("normalized time = %v, want same instant as %v", normalized, local)
	}
	if got := NormalizeTimestamp(time.Time{}); !got.IsZero() {
		t.Fatalf("zero normalized to %v, want zero", got)
	}
}

func TestExpiryConventions(t *testing.T) {
	now := time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)
	expiry := NewExpiry(now, time.Minute)

	if expiry.IsExpired(now.Add(59 * time.Second)) {
		t.Fatal("expiry elapsed before ExpiresAt")
	}
	if !expiry.IsExpired(now.Add(time.Minute)) {
		t.Fatal("expiry should be exclusive at ExpiresAt")
	}
	if !expiry.IsExpired(now.Add(2 * time.Minute)) {
		t.Fatal("expiry should elapse after ExpiresAt")
	}
	if !IsExpired(now, time.Time{}) {
		t.Fatal("zero ExpiresAt should fail closed as expired")
	}
	if got := expiry.Remaining(now.Add(30 * time.Second)); got != 30*time.Second {
		t.Fatalf("remaining = %s, want 30s", got)
	}
	if got := expiry.Remaining(now.Add(time.Minute)); got != 0 {
		t.Fatalf("remaining after expiry = %s, want 0", got)
	}
}
