package password

import (
	"context"
	"unicode/utf8"

	"github.com/KernelFreeze/aether-auth/internal/auth"
)

const (
	defaultMinLength = 8
	defaultMaxLength = 128
)

// NISTPolicy enforces length limits without character-class rules.
type NISTPolicy struct {
	MinLength int
	MaxLength int
}

var _ auth.PasswordPolicy = NISTPolicy{}

// CheckPasswordPolicy checks the local password rules.
func (p NISTPolicy) CheckPasswordPolicy(_ context.Context, req auth.PasswordPolicyRequest) (auth.PasswordPolicyResult, error) {
	minLength := p.MinLength
	if minLength <= 0 {
		minLength = defaultMinLength
	}
	maxLength := p.MaxLength
	if maxLength <= 0 {
		maxLength = defaultMaxLength
	}

	length := utf8.RuneCountInString(req.Password)
	var violations []string
	if length < minLength {
		violations = append(violations, "too_short")
	}
	if length > maxLength {
		violations = append(violations, "too_long")
	}
	return auth.PasswordPolicyResult{
		Allowed:    len(violations) == 0,
		Violations: violations,
	}, nil
}
