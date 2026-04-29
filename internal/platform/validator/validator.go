// Package validator wraps go-playground/validator with the project's
// conventions (lowercased field names, structured error responses).
package validator

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

// ValidationError is a single field-level validation failure surfaced to the
// HTTP client.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Validator runs struct validation and translates errors into the project's
// ValidationError format.
type Validator struct {
	v *validator.Validate
}

// New constructs a Validator using the library defaults; the built-in "email"
// tag from go-playground/validator already covers RFC-style email validation.
func New() *Validator {
	return &Validator{v: validator.New()}
}

// Struct validates the given struct and returns the list of field errors. An
// empty slice means the input is valid.
func (vd *Validator) Struct(i any) []ValidationError {
	err := vd.v.Struct(i)
	if err == nil {
		return nil
	}
	verrs, ok := err.(validator.ValidationErrors)
	if !ok {
		return []ValidationError{{Field: "", Message: err.Error()}}
	}
	out := make([]ValidationError, 0, len(verrs))
	for _, fe := range verrs {
		out = append(out, ValidationError{
			Field:   strings.ToLower(fe.Field()),
			Message: messageFor(fe),
		})
	}
	return out
}

func messageFor(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return "Value must be greater than " + fe.Param()
	case "max":
		return "Value must be less than " + fe.Param()
	default:
		return "Invalid value"
	}
}
