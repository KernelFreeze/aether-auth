package passwordreset

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

const (
	errorIDResetInvalid       auth.ErrorID = "AUTH-RESET-0002"
	errorIDResetNotConfigured auth.ErrorID = "AUTH-RESET-0003"
)

func (m *Module) handleRequestReset(c *gin.Context) {
	if m.requester == nil {
		writeResetProblem(c, http.StatusNotImplemented, "reset_not_configured", "Reset not configured", "Password reset is not wired.", errorIDResetNotConfigured)
		return
	}

	req, err := decodeRequestReset(c)
	if err != nil {
		writeRequestResetError(c, err)
		return
	}
	if _, err := m.requester.RequestReset(c.Request.Context(), req); err != nil {
		writeRequestResetError(c, err)
		return
	}
	httpx.WritePasswordResetAccepted(c)
}

type requestResetBody struct {
	Identifier string `json:"identifier"`
	Username   string `json:"username"`
	Email      string `json:"email"`
}

func decodeRequestReset(c *gin.Context) (RequestResetRequest, error) {
	var body requestResetBody
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return RequestResetRequest{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "reset body must be valid JSON", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return RequestResetRequest{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "reset body must contain one JSON object", nil)
	}
	return RequestResetRequest{
		Identifier: body.Identifier,
		Username:   body.Username,
		Email:      body.Email,
		IP:         c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
		RequestID:  middleware.RequestID(c),
	}, nil
}

func writeRequestResetError(c *gin.Context, err error) {
	if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrLockedAccount) || errors.Is(err, auth.ErrMalformedInput) {
		httpx.WritePasswordResetAccepted(c)
		return
	}
	writeResetProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", auth.ErrorIDInternal)
}

func writeResetProblem(c *gin.Context, status int, code, title, detail string, id auth.ErrorID) {
	httpx.WriteProblem(c, httpx.Problem{
		Type:    "https://aether-auth.local/problems/" + code,
		Title:   title,
		Status:  status,
		Code:    code,
		Detail:  detail,
		ErrorID: string(id),
	})
}
