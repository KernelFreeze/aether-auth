// pkg/validator/validator.go
package validator

import (
	"log"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

var (
	validate   *validator.Validate
	emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
)

func init() {
	validate = validator.New()

	// Register custom validation
	err := validate.RegisterValidation("email", validateEmail)
	if err != nil {
		log.Print(err)
	}
}

func validateEmail(fl validator.FieldLevel) bool {
	return emailRegex.MatchString(fl.Field().String())
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Validate validates a struct and returns validation errors
func Validate(i interface{}) []ValidationError {
	var errors []ValidationError

	err := validate.Struct(i)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var element ValidationError
			element.Field = strings.ToLower(err.Field())
			element.Message = generateValidationMessage(err)
			errors = append(errors, element)
		}
	}

	return errors
}

func generateValidationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return "Value must be greater than " + err.Param()
	case "max":
		return "Value must be less than " + err.Param()
	default:
		return "Invalid value"
	}
}
