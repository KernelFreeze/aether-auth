package account

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/authctx"
)

func (m *Module) handleEnrollTOTP(c *gin.Context) {
	if m.totp == nil || m.profiles == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "mfa_not_configured", "MFA not configured", "TOTP enrollment is not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}
	var body enrollTOTPRequest
	if err := decodeOptionalJSON(c, &body); err != nil {
		writeAccountMFAError(c, err)
		return
	}
	profile, err := m.profiles.GetProfile(c.Request.Context(), accountID)
	if err != nil {
		writeAccountError(c, err)
		return
	}

	enrollment, err := m.totp.EnrollTOTP(c.Request.Context(), TOTPEnrollmentRequest{
		AccountID:   accountID,
		Issuer:      body.Issuer,
		AccountName: profile.Username,
	})
	if err != nil {
		writeAccountMFAError(c, err)
		return
	}
	c.JSON(http.StatusCreated, totpEnrollmentResponse{
		CredentialID:    enrollment.CredentialID.String(),
		ProvisioningURI: enrollment.ProvisioningURI,
		Secret:          enrollment.Secret,
	})
}

func (m *Module) handleConfirmTOTP(c *gin.Context) {
	if m.totp == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "mfa_not_configured", "MFA not configured", "TOTP confirmation is not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}
	body, err := decodeConfirmTOTP(c)
	if err != nil {
		writeAccountMFAError(c, err)
		return
	}
	credential, err := m.totp.ConfirmTOTP(c.Request.Context(), TOTPConfirmRequest{
		AccountID:    accountID,
		CredentialID: body.credentialID,
		Code:         body.Code,
		Endpoint:     c.FullPath(),
	})
	if err != nil {
		writeAccountMFAError(c, err)
		return
	}
	c.JSON(http.StatusOK, totpCredentialResponse{
		CredentialID: credential.ID.String(),
		Kind:         credential.Kind.String(),
		Verified:     credential.Verified,
	})
}

func (m *Module) handleDisableTOTP(c *gin.Context) {
	if m.credentials == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "credentials_not_configured", "Credentials not configured", "Credential routes are not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}
	credentialID, err := ParseCredentialID(c.Param("credential_id"))
	if err != nil {
		writeAccountProblem(c, http.StatusBadRequest, "invalid_credential_id", "Invalid credential ID", "The credential ID is malformed.", nil)
		return
	}
	if !m.accountHasCredentialKind(c, accountID, credentialID, CredentialKindTOTP) {
		return
	}

	reauthenticatedAt, _ := authctx.ReauthenticatedAt(c)
	_, err = m.credentials.RemoveCredential(c.Request.Context(), RemoveCredentialRequest{
		AccountID:         accountID,
		CredentialID:      credentialID,
		ReauthenticatedAt: reauthenticatedAt,
	})
	if err != nil {
		writeAccountError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (m *Module) handleRegenerateRecoveryCodes(c *gin.Context) {
	if m.totp == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "mfa_not_configured", "MFA not configured", "Recovery-code regeneration is not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}
	body, err := decodeRegenerateRecoveryCodes(c)
	if err != nil {
		writeAccountMFAError(c, err)
		return
	}
	generated, err := m.totp.GenerateRecoveryCodes(c.Request.Context(), RecoveryCodeGenerateRequest{
		AccountID:    accountID,
		CredentialID: body.credentialID,
	})
	if err != nil {
		writeAccountMFAError(c, err)
		return
	}
	c.JSON(http.StatusOK, recoveryCodesResponse{
		CredentialID: generated.CredentialID.String(),
		Codes:        append([]string(nil), generated.Codes...),
	})
}

type enrollTOTPRequest struct {
	Issuer string `json:"issuer"`
}

type confirmTOTPRequest struct {
	CredentialID string `json:"credential_id"`
	Code         string `json:"code"`
	credentialID CredentialID
}

type regenerateRecoveryCodesRequest struct {
	CredentialID string `json:"credential_id"`
	credentialID CredentialID
}

type totpEnrollmentResponse struct {
	CredentialID    string `json:"credential_id"`
	ProvisioningURI string `json:"provisioning_uri"`
	Secret          string `json:"secret"`
}

type totpCredentialResponse struct {
	CredentialID string `json:"credential_id"`
	Kind         string `json:"kind"`
	Verified     bool   `json:"verified"`
}

type recoveryCodesResponse struct {
	CredentialID string   `json:"credential_id"`
	Codes        []string `json:"codes"`
}

func decodeOptionalJSON(c *gin.Context, out any) error {
	if c.Request.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return ErrMalformedMFA
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrMalformedMFA
	}
	return nil
}

func decodeConfirmTOTP(c *gin.Context) (confirmTOTPRequest, error) {
	var body confirmTOTPRequest
	if err := decodeOptionalJSON(c, &body); err != nil {
		return confirmTOTPRequest{}, err
	}
	credentialID, err := ParseCredentialID(body.CredentialID)
	if err != nil {
		return confirmTOTPRequest{}, ErrMalformedMFA
	}
	if strings.TrimSpace(body.Code) == "" {
		return confirmTOTPRequest{}, ErrMalformedMFA
	}
	body.credentialID = credentialID
	return body, nil
}

func decodeRegenerateRecoveryCodes(c *gin.Context) (regenerateRecoveryCodesRequest, error) {
	var body regenerateRecoveryCodesRequest
	if err := decodeOptionalJSON(c, &body); err != nil {
		return regenerateRecoveryCodesRequest{}, err
	}
	if strings.TrimSpace(body.CredentialID) == "" {
		return body, nil
	}
	credentialID, err := ParseCredentialID(body.CredentialID)
	if err != nil {
		return regenerateRecoveryCodesRequest{}, ErrMalformedMFA
	}
	body.credentialID = credentialID
	return body, nil
}

func (m *Module) accountHasCredentialKind(c *gin.Context, accountID AccountID, credentialID CredentialID, kind CredentialKind) bool {
	credentials, err := m.credentials.ListCredentials(c.Request.Context(), accountID)
	if err != nil {
		writeAccountError(c, err)
		return false
	}
	for _, credential := range credentials {
		if credential.ID == credentialID && credential.Kind == kind {
			return true
		}
	}
	writeAccountProblem(c, http.StatusNotFound, "credential_not_found", "Credential not found", "The credential was not found.", nil)
	return false
}

func writeAccountMFAError(c *gin.Context, err error) {
	if errors.Is(err, ErrInvalidMFA) {
		writeAccountProblem(c, http.StatusUnauthorized, "invalid_mfa", "Invalid MFA code", "The MFA verification could not be completed.", nil)
		return
	}
	if errors.Is(err, ErrMalformedMFA) {
		writeAccountProblem(c, http.StatusBadRequest, "invalid_mfa_request", "Invalid MFA request", "The MFA request is invalid.", nil)
		return
	}
	writeAccountProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", nil)
}
