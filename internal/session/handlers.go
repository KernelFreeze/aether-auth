package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

const (
	errorIDRefreshInvalid       = "SESSION-REFRESH-0001"
	errorIDRefreshNotConfigured = "SESSION-REFRESH-0002"
	errorIDRefreshInternal      = "SESSION-REFRESH-0003"
)

func (m *Module) handleRefresh(c *gin.Context) {
	if m.refresher == nil {
		writeSessionProblem(c, http.StatusNotImplemented, "refresh_not_configured", "Refresh not configured", "Refresh token rotation is not wired.", errorIDRefreshNotConfigured)
		return
	}

	req, err := decodeRefresh(c)
	if err != nil {
		writeRefreshError(c, err)
		return
	}
	result, err := m.refresher.RefreshSession(c.Request.Context(), req)
	if err != nil {
		writeRefreshError(c, err)
		return
	}
	c.JSON(http.StatusOK, refreshResponse{
		Status: "refreshed",
		Session: refreshSessionResponse{
			ID:           result.SessionID.String(),
			AccessToken:  result.AccessToken,
			RefreshToken: result.RefreshToken,
			ExpiresAt:    account.NormalizeTimestamp(result.ExpiresAt),
		},
	})
}

type refreshRequestBody struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	Status  string                 `json:"status"`
	Session refreshSessionResponse `json:"session"`
}

type refreshSessionResponse struct {
	ID           string    `json:"id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func decodeRefresh(c *gin.Context) (RefreshSessionRequest, error) {
	var body refreshRequestBody
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return RefreshSessionRequest{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "refresh body must be valid JSON", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return RefreshSessionRequest{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "refresh body must contain one JSON object", nil)
	}
	if strings.TrimSpace(body.RefreshToken) == "" {
		return RefreshSessionRequest{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "refresh token is required", nil)
	}
	return RefreshSessionRequest{RefreshToken: body.RefreshToken, Now: time.Now()}, nil
}

func writeRefreshError(c *gin.Context, err error) {
	if errors.Is(err, auth.ErrInvalidCredentials) {
		writeSessionProblem(c, http.StatusUnauthorized, "invalid_refresh_token", "Invalid refresh token", "The refresh token is invalid.", errorIDRefreshInvalid)
		return
	}
	if errors.Is(err, auth.ErrMalformedInput) {
		writeSessionProblem(c, http.StatusBadRequest, "invalid_refresh", "Invalid refresh", "The refresh request is invalid.", errorIDRefreshInvalid)
		return
	}
	writeSessionProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", errorIDRefreshInternal)
}

func writeSessionProblem(c *gin.Context, status int, code, title, detail, id string) {
	httpx.WriteProblem(c, httpx.Problem{
		Type:    fmt.Sprintf("https://aether-auth.local/problems/%s", code),
		Title:   title,
		Status:  status,
		Code:    code,
		Detail:  detail,
		ErrorID: id,
	})
}
