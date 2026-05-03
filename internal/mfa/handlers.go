package mfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/auth"
	"github.com/KernelFreeze/aether-auth/internal/auth/totp"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

const (
	errorIDMFAVerifyInvalid       auth.ErrorID = "AUTH-MFA-0001"
	errorIDMFAVerifyNotConfigured auth.ErrorID = "AUTH-MFA-0002"
	errorIDMFAVerifyInternal      auth.ErrorID = "AUTH-MFA-0003"
)

func (m *Module) handleVerify(c *gin.Context) {
	if m.policy == nil || m.partialSessions == nil || m.totp == nil {
		writeMFAProblem(c, http.StatusNotImplemented, "mfa_not_configured", "MFA not configured", "MFA verification is not wired.", errorIDMFAVerifyNotConfigured)
		return
	}

	body, err := decodeVerify(c)
	if err != nil {
		writeMFAError(c, err)
		return
	}
	partial, err := m.partialSessions.VerifyPartialSession(c.Request.Context(), auth.PartialSessionVerifyRequest{
		SessionID: body.partialSessionID,
		Token:     body.partialToken,
		Now:       time.Now(),
	})
	if err != nil {
		writeMFAError(c, err)
		return
	}

	state, err := m.accountState(c, partial.AccountID)
	if err != nil {
		writeMFAError(c, err)
		return
	}
	if state.Disabled || state.Locked(time.Now()) {
		writeMFAError(c, auth.ErrInvalidCredentials)
		return
	}

	check, err := m.verifyFactor(c, partial, body)
	if err != nil {
		writeMFAError(c, err)
		return
	}
	partial.VerifiedFactors = NormalizeFactorKinds(append(partial.VerifiedFactors, check.Kind))
	partial.ChallengeBindings = append(partial.ChallengeBindings, check.ChallengeBinding)

	upgraded, err := m.policy.Upgrade(c.Request.Context(), UpgradeRequest{
		PartialSession:     partial,
		AccountMFAEnforced: state.MFARequired,
		IP:                 c.ClientIP(),
		UserAgent:          c.Request.UserAgent(),
		Now:                time.Now(),
	})
	if err != nil {
		writeMFAError(c, err)
		return
	}

	c.JSON(http.StatusOK, verifyResponse{
		Status: "authenticated",
		Session: verifySessionResponse{
			ID:           upgraded.Session.SessionID.String(),
			AccessToken:  upgraded.Session.AccessToken,
			RefreshToken: upgraded.Session.RefreshToken,
			ExpiresAt:    account.NormalizeTimestamp(upgraded.Session.ExpiresAt),
		},
	})
}

type verifyRequestBody struct {
	PartialSessionID    string `json:"partial_session_id"`
	SessionID           string `json:"session_id"`
	PartialToken        string `json:"partial_token"`
	PartialSessionToken string `json:"partial_session_token"`
	Kind                string `json:"kind"`
	CredentialID        string `json:"credential_id"`
	Code                string `json:"code"`

	partialSessionID account.SessionID
	partialToken     string
	credentialID     account.CredentialID
	factor           account.FactorKind
}

type verifyResponse struct {
	Status  string                `json:"status"`
	Session verifySessionResponse `json:"session"`
}

type verifySessionResponse struct {
	ID           string    `json:"id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func decodeVerify(c *gin.Context) (verifyRequestBody, error) {
	var body verifyRequestBody
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa body must be valid JSON", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa body must contain one JSON object", nil)
	}

	sessionID := strings.TrimSpace(body.PartialSessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(body.SessionID)
	}
	parsedSessionID, err := account.ParseSessionID(sessionID)
	if err != nil {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "partial session id is invalid", err)
	}
	body.partialSessionID = parsedSessionID

	body.partialToken = strings.TrimSpace(body.PartialToken)
	if body.partialToken == "" {
		body.partialToken = strings.TrimSpace(body.PartialSessionToken)
	}
	if body.partialToken == "" {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "partial token is required", nil)
	}

	factor, err := account.ParseFactorKind(body.Kind)
	if err != nil {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa factor kind is invalid", err)
	}
	if factor != account.FactorKindTOTP && factor != account.FactorKindRecoveryCode {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa factor kind is not supported", nil)
	}
	body.factor = factor

	if strings.TrimSpace(body.CredentialID) != "" {
		credentialID, err := account.ParseCredentialID(body.CredentialID)
		if err != nil {
			return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "credential id is invalid", err)
		}
		body.credentialID = credentialID
	}
	if strings.TrimSpace(body.Code) == "" {
		return verifyRequestBody{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa code is required", nil)
	}

	return body, nil
}

func (m *Module) accountState(c *gin.Context, accountID account.AccountID) (auth.AccountState, error) {
	if m.accounts == nil {
		return auth.AccountState{AccountID: accountID, MFARequired: true}, nil
	}
	state, err := m.accounts.AccountState(c.Request.Context(), accountID)
	if err != nil {
		return auth.AccountState{}, err
	}
	if state.AccountID.IsZero() {
		state.AccountID = accountID
	}
	return state, nil
}

func (m *Module) verifyFactor(c *gin.Context, partial auth.PartialSession, body verifyRequestBody) (auth.FactorCheck, error) {
	ip, _ := netip.ParseAddr(c.ClientIP())
	binding := partial.ID.String()
	switch body.factor {
	case account.FactorKindTOTP:
		check, _, err := m.totp.VerifyTOTP(c.Request.Context(), totp.VerifyTOTPRequest{
			AccountID:        partial.AccountID,
			CredentialID:     body.credentialID,
			Code:             body.Code,
			IP:               ip,
			UserAgent:        c.Request.UserAgent(),
			Endpoint:         c.FullPath(),
			RequestID:        middleware.RequestID(c),
			ChallengeBinding: binding,
		})
		return check, err
	case account.FactorKindRecoveryCode:
		check, _, err := m.totp.VerifyRecoveryCode(c.Request.Context(), totp.VerifyRecoveryCodeRequest{
			AccountID:        partial.AccountID,
			CredentialID:     body.credentialID,
			Code:             body.Code,
			IP:               ip,
			UserAgent:        c.Request.UserAgent(),
			Endpoint:         c.FullPath(),
			ChallengeBinding: binding,
		})
		return check, err
	default:
		return auth.FactorCheck{}, auth.NewServiceError(auth.ErrorKindMalformedInput, "mfa factor kind is not supported", nil)
	}
}

func writeMFAError(c *gin.Context, err error) {
	if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrLockedAccount) || errors.Is(err, auth.ErrPolicyDenied) {
		writeMFAProblem(c, http.StatusUnauthorized, "invalid_mfa", "Invalid MFA code", "The MFA verification could not be completed.", errorIDMFAVerifyInvalid)
		return
	}
	if errors.Is(err, auth.ErrMalformedInput) || authKindIs(err, auth.ErrorKindMalformedInput) {
		writeMFAProblem(c, http.StatusBadRequest, "invalid_mfa_request", "Invalid MFA request", "The MFA verification request is invalid.", errorIDMFAVerifyInvalid)
		return
	}
	writeMFAProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", errorIDMFAVerifyInternal)
}

func authKindIs(err error, kind auth.ErrorKind) bool {
	got, ok := auth.ErrorKindOf(err)
	return ok && got == kind
}

func writeMFAProblem(c *gin.Context, status int, code, title, detail string, id auth.ErrorID) {
	httpx.WriteProblem(c, httpx.Problem{
		Type:    fmt.Sprintf("https://aether-auth.local/problems/%s", code),
		Title:   title,
		Status:  status,
		Code:    code,
		Detail:  detail,
		ErrorID: string(id),
	})
}
