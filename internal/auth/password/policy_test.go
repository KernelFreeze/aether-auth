package password

import (
	"context"
	"strings"
	"testing"

	"github.com/KernelFreeze/aether-auth/internal/auth"
)

func TestNISTPolicyAllowsUnicodeAndDoesNotRequireComposition(t *testing.T) {
	result, err := (NISTPolicy{}).CheckPasswordPolicy(context.Background(), auth.PasswordPolicyRequest{
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("check policy: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("policy result = %#v, want allowed", result)
	}

	result, err = (NISTPolicy{}).CheckPasswordPolicy(context.Background(), auth.PasswordPolicyRequest{
		Password: "        ",
	})
	if err != nil {
		t.Fatalf("check spaces policy: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("spaces-only password should pass length policy: %#v", result)
	}
}

func TestNISTPolicyRejectsLengthViolations(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		violation string
	}{
		{name: "short", password: "short", violation: "too_short"},
		{name: "long", password: strings.Repeat("a", 129), violation: "too_long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := (NISTPolicy{}).CheckPasswordPolicy(context.Background(), auth.PasswordPolicyRequest{Password: tt.password})
			if err != nil {
				t.Fatalf("check policy: %v", err)
			}
			if result.Allowed || len(result.Violations) != 1 || result.Violations[0] != tt.violation {
				t.Fatalf("policy result = %#v, want %s", result, tt.violation)
			}
		})
	}
}
