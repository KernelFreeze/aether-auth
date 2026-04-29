package validator_test

import (
	"testing"

	projectvalidator "github.com/KernelFreeze/aether-auth/internal/platform/validator"
)

func TestValidatorStruct(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		wantField   string
		wantMessage string
	}{
		{
			name: "valid",
			input: struct {
				Email string `validate:"required,email"`
			}{Email: "user@example.com"},
		},
		{
			name: "required",
			input: struct {
				DisplayName string `validate:"required"`
			}{},
			wantField:   "displayname",
			wantMessage: "This field is required",
		},
		{
			name: "email",
			input: struct {
				Email string `validate:"email"`
			}{Email: "not-an-email"},
			wantField:   "email",
			wantMessage: "Invalid email format",
		},
		{
			name: "min",
			input: struct {
				Password string `validate:"min=8"`
			}{Password: "short"},
			wantField:   "password",
			wantMessage: "Value must be greater than 8",
		},
		{
			name: "max",
			input: struct {
				Username string `validate:"max=4"`
			}{Username: "longer"},
			wantField:   "username",
			wantMessage: "Value must be less than 4",
		},
	}

	vd := projectvalidator.New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := vd.Struct(tt.input)
			if tt.wantField == "" {
				if len(errs) != 0 {
					t.Fatalf("Struct() = %#v, want no errors", errs)
				}
				return
			}
			if len(errs) != 1 {
				t.Fatalf("Struct() error count = %d, want 1: %#v", len(errs), errs)
			}
			if errs[0].Field != tt.wantField {
				t.Fatalf("Field = %q, want %q", errs[0].Field, tt.wantField)
			}
			if errs[0].Message != tt.wantMessage {
				t.Fatalf("Message = %q, want %q", errs[0].Message, tt.wantMessage)
			}
		})
	}
}

func TestValidatorStructInvalidInput(t *testing.T) {
	errs := projectvalidator.New().Struct(nil)
	if len(errs) != 1 {
		t.Fatalf("Struct(nil) error count = %d, want 1", len(errs))
	}
	if errs[0].Field != "" {
		t.Fatalf("Field = %q, want empty field", errs[0].Field)
	}
}
