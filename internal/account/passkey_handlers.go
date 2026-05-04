package account

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
)

func (m *Module) handleBeginPasskeyRegistration(c *gin.Context) {
	if m.passkeys == nil || m.profiles == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "passkey_not_configured", "Passkey registration not configured", "Passkey registration is not wired.", nil)
		return
	}
	accountID, sessionID, ok := authenticatedAccountSession(c)
	if !ok {
		return
	}
	body, err := decodeBeginPasskeyRegistration(c)
	if err != nil {
		writeAccountPasskeyError(c, err)
		return
	}
	profile, err := m.profiles.GetProfile(c.Request.Context(), accountID)
	if err != nil {
		writeAccountError(c, err)
		return
	}

	result, err := m.passkeys.BeginPasskeyRegistration(c.Request.Context(), PasskeyRegistrationBeginRequest{
		AccountID:               accountID,
		SessionID:               sessionID,
		Username:                profile.Username,
		DisplayName:             profile.DisplayName,
		RequestID:               middleware.RequestID(c),
		UserVerification:        body.UserVerification,
		AuthenticatorAttachment: body.AuthenticatorAttachment,
	})
	if err != nil {
		writeAccountPasskeyError(c, err)
		return
	}
	c.JSON(http.StatusCreated, passkeyRegistrationOptionsResponse{
		ChallengeID: result.ChallengeID,
		ExpiresAt:   NormalizeTimestamp(result.ExpiresAt),
		Options:     json.RawMessage(result.Options),
	})
}

func (m *Module) handleFinishPasskeyRegistration(c *gin.Context) {
	if m.passkeys == nil || m.profiles == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "passkey_not_configured", "Passkey registration not configured", "Passkey registration is not wired.", nil)
		return
	}
	accountID, sessionID, ok := authenticatedAccountSession(c)
	if !ok {
		return
	}
	body, err := decodeFinishPasskeyRegistration(c)
	if err != nil {
		writeAccountPasskeyError(c, err)
		return
	}
	profile, err := m.profiles.GetProfile(c.Request.Context(), accountID)
	if err != nil {
		writeAccountError(c, err)
		return
	}

	credential, err := m.passkeys.FinishPasskeyRegistration(c.Request.Context(), PasskeyRegistrationFinishRequest{
		AccountID:           accountID,
		SessionID:           sessionID,
		Username:            profile.Username,
		DisplayName:         profile.DisplayName,
		ChallengeID:         body.ChallengeID,
		CredentialName:      body.CredentialName,
		AttestationResponse: body.AttestationResponse,
	})
	if err != nil {
		writeAccountPasskeyError(c, err)
		return
	}
	c.JSON(http.StatusCreated, passkeyCredentialResponse{
		CredentialID: credential.ID.String(),
		Kind:         credential.Kind.String(),
		DisplayName:  credential.DisplayName,
		Verified:     credential.Verified,
		CreatedAt:    NormalizeTimestamp(credential.CreatedAt),
	})
}

type beginPasskeyRegistrationRequest struct {
	UserVerification        string `json:"user_verification"`
	AuthenticatorAttachment string `json:"authenticator_attachment"`
}

type finishPasskeyRegistrationRequest struct {
	ChallengeID         string          `json:"challenge_id"`
	CredentialName      string          `json:"credential_name"`
	AttestationResponse json.RawMessage `json:"attestation_response"`
}

type passkeyRegistrationOptionsResponse struct {
	ChallengeID string          `json:"challenge_id"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Options     json.RawMessage `json:"options"`
}

type passkeyCredentialResponse struct {
	CredentialID string    `json:"credential_id"`
	Kind         string    `json:"kind"`
	DisplayName  string    `json:"display_name"`
	Verified     bool      `json:"verified"`
	CreatedAt    time.Time `json:"created_at"`
}

func authenticatedAccountSession(c *gin.Context) (AccountID, SessionID, bool) {
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return AccountID{}, SessionID{}, false
	}
	sessionID, ok := authenticatedSessionID(c)
	if !ok {
		writeAccountProblem(c, http.StatusUnauthorized, "authentication_required", "Authentication required", "A valid account session is required.", nil)
		return AccountID{}, SessionID{}, false
	}
	return accountID, sessionID, true
}

func decodeBeginPasskeyRegistration(c *gin.Context) (beginPasskeyRegistrationRequest, error) {
	var body beginPasskeyRegistrationRequest
	if err := decodePasskeyJSON(c, &body); err != nil {
		return beginPasskeyRegistrationRequest{}, err
	}
	body.UserVerification = strings.TrimSpace(body.UserVerification)
	body.AuthenticatorAttachment = strings.TrimSpace(body.AuthenticatorAttachment)
	switch body.UserVerification {
	case "", "required", "preferred", "discouraged":
	default:
		return beginPasskeyRegistrationRequest{}, ErrMalformedPasskey
	}
	switch body.AuthenticatorAttachment {
	case "", "platform", "cross-platform":
	default:
		return beginPasskeyRegistrationRequest{}, ErrMalformedPasskey
	}
	return body, nil
}

func decodeFinishPasskeyRegistration(c *gin.Context) (finishPasskeyRegistrationRequest, error) {
	var body finishPasskeyRegistrationRequest
	if err := decodePasskeyJSON(c, &body); err != nil {
		return finishPasskeyRegistrationRequest{}, err
	}
	body.ChallengeID = strings.TrimSpace(body.ChallengeID)
	body.CredentialName = strings.TrimSpace(body.CredentialName)
	body.AttestationResponse = bytes.TrimSpace(body.AttestationResponse)
	if body.ChallengeID == "" || len(body.AttestationResponse) == 0 || body.AttestationResponse[0] != '{' {
		return finishPasskeyRegistrationRequest{}, ErrMalformedPasskey
	}
	return body, nil
}

func decodePasskeyJSON(c *gin.Context, out any) error {
	if c.Request.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return ErrMalformedPasskey
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrMalformedPasskey
	}
	return nil
}

func writeAccountPasskeyError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrMalformedPasskey):
		writeAccountProblem(c, http.StatusBadRequest, "invalid_passkey_request", "Invalid passkey request", "The passkey request is invalid.", nil)
	case errors.Is(err, ErrExpiredPasskeyChallenge):
		writeAccountProblem(c, http.StatusBadRequest, "expired_passkey_challenge", "Expired passkey challenge", "The passkey challenge has expired.", nil)
	case errors.Is(err, ErrReplayedPasskeyChallenge):
		writeAccountProblem(c, http.StatusBadRequest, "replayed_passkey_challenge", "Replayed passkey challenge", "The passkey challenge has already been used.", nil)
	case errors.Is(err, ErrInvalidPasskey):
		writeAccountProblem(c, http.StatusUnauthorized, "invalid_passkey", "Invalid passkey", "The passkey registration could not be completed.", nil)
	default:
		writeAccountProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", nil)
	}
}
