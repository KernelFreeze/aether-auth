package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

const (
	errorIDRegistrationInvalid       ErrorID = "AUTH-REGISTER-0001"
	errorIDRegistrationNotConfigured ErrorID = "AUTH-REGISTER-0002"
)

func (m *Module) handleRegister(c *gin.Context) {
	if m.registration == nil {
		writeAuthProblem(c, http.StatusNotImplemented, "registration_not_configured", "Registration not configured", "Registration is not wired.", nil, errorIDRegistrationNotConfigured)
		return
	}

	req, err := decodeRegistration(c)
	if err != nil {
		writeRegistrationError(c, err)
		return
	}

	result, err := m.registration.Register(c.Request.Context(), req)
	if err != nil {
		writeRegistrationError(c, err)
		return
	}
	message := result.PublicMessage
	if message == "" {
		message = account.RegistrationAcceptedMessage
	}
	c.JSON(http.StatusAccepted, registrationResponse{Message: message})
}

type registerRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type registrationResponse struct {
	Message string `json:"message"`
}

func decodeRegistration(c *gin.Context) (account.RegistrationRequest, error) {
	var body registerRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return account.RegistrationRequest{}, &account.RegistrationValidationError{
			Fields: []account.RegistrationFieldError{{Field: "body", Reason: "must be valid JSON"}},
		}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return account.RegistrationRequest{}, &account.RegistrationValidationError{
			Fields: []account.RegistrationFieldError{{Field: "body", Reason: "must contain one JSON object"}},
		}
	}

	return account.RegistrationRequest{
		Username:    body.Username,
		Email:       body.Email,
		DisplayName: body.DisplayName,
		RequestID:   middleware.RequestID(c),
		IP:          c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
	}, nil
}

func writeRegistrationError(c *gin.Context, err error) {
	if errors.Is(err, account.ErrInvalidRegistration) {
		var validationErr *account.RegistrationValidationError
		var fields []httpx.ProblemField
		if errors.As(err, &validationErr) {
			fields = make([]httpx.ProblemField, 0, len(validationErr.Fields))
			for _, field := range validationErr.Fields {
				fields = append(fields, httpx.ProblemField{Name: field.Field, Reason: field.Reason})
			}
		}
		writeAuthProblem(c, http.StatusBadRequest, "invalid_registration", "Invalid registration", "The registration request is invalid.", fields, errorIDRegistrationInvalid)
		return
	}
	writeAuthProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", nil, ErrorIDInternal)
}

func writeAuthProblem(c *gin.Context, status int, code, title, detail string, fields []httpx.ProblemField, id ErrorID) {
	httpx.WriteProblem(c, httpx.Problem{
		Type:    fmt.Sprintf("https://aether-auth.local/problems/%s", code),
		Title:   title,
		Status:  status,
		Code:    code,
		Detail:  detail,
		Fields:  fields,
		ErrorID: string(id),
	})
}
