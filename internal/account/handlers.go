package account

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/authctx"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

func authenticationNotConfigured(c *gin.Context) {
	writeAccountProblem(c, http.StatusNotImplemented, "authentication_not_configured", "Authentication not configured", "Authentication middleware is not wired for this route.", nil)
}

func (m *Module) handleGetProfile(c *gin.Context) {
	if m.profiles == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "profile_not_configured", "Profile not configured", "Profile routes are not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}

	profile, err := m.profiles.GetProfile(c.Request.Context(), accountID)
	if err != nil {
		writeAccountError(c, err)
		return
	}
	c.JSON(http.StatusOK, profileResponseFrom(profile))
}

func (m *Module) handleUpdateProfile(c *gin.Context) {
	if m.profiles == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "profile_not_configured", "Profile not configured", "Profile routes are not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}

	req, err := decodeProfileUpdate(c, accountID)
	if err != nil {
		writeAccountError(c, err)
		return
	}
	profile, err := m.profiles.UpdateProfile(c.Request.Context(), req)
	if err != nil {
		writeAccountError(c, err)
		return
	}
	c.JSON(http.StatusOK, profileResponseFrom(profile))
}

func (m *Module) handleListCredentials(c *gin.Context) {
	if m.credentials == nil {
		writeAccountProblem(c, http.StatusNotImplemented, "credentials_not_configured", "Credentials not configured", "Credential routes are not wired.", nil)
		return
	}
	accountID, ok := authenticatedAccountID(c)
	if !ok {
		return
	}

	credentials, err := m.credentials.ListCredentials(c.Request.Context(), accountID)
	if err != nil {
		writeAccountError(c, err)
		return
	}
	response := credentialsResponse{Credentials: make([]credentialResponse, 0, len(credentials))}
	for _, credential := range credentials {
		response.Credentials = append(response.Credentials, credentialResponseFrom(credential))
	}
	c.JSON(http.StatusOK, response)
}

func (m *Module) handleRemoveCredential(c *gin.Context) {
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

type profileResponse struct {
	ID          string          `json:"id"`
	Username    string          `json:"username"`
	DisplayName string          `json:"display_name"`
	Metadata    json.RawMessage `json:"metadata"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func profileResponseFrom(profile AccountProfile) profileResponse {
	metadata := profile.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	return profileResponse{
		ID:          profile.ID.String(),
		Username:    profile.Username,
		DisplayName: profile.DisplayName,
		Metadata:    metadata,
		CreatedAt:   NormalizeTimestamp(profile.CreatedAt),
		UpdatedAt:   NormalizeTimestamp(profile.UpdatedAt),
	}
}

type credentialsResponse struct {
	Credentials []credentialResponse `json:"credentials"`
}

type credentialResponse struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Provider    string     `json:"provider,omitempty"`
	DisplayName string     `json:"display_name"`
	Verified    bool       `json:"verified"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func credentialResponseFrom(credential Credential) credentialResponse {
	response := credentialResponse{
		ID:          credential.ID.String(),
		Kind:        credential.Kind.String(),
		Provider:    credential.Provider,
		DisplayName: credential.DisplayName,
		Verified:    credential.Verified,
		CreatedAt:   NormalizeTimestamp(credential.CreatedAt),
		UpdatedAt:   NormalizeTimestamp(credential.UpdatedAt),
	}
	if lastUsed := NormalizeTimestamp(credential.LastUsedAt); !lastUsed.IsZero() {
		response.LastUsedAt = &lastUsed
	}
	return response
}

func authenticatedAccountID(c *gin.Context) (AccountID, bool) {
	value, ok := authctx.AccountID(c)
	if !ok {
		writeAccountProblem(c, http.StatusUnauthorized, "authentication_required", "Authentication required", "A valid account session is required.", nil)
		return AccountID{}, false
	}
	accountID, err := ParseAccountID(value)
	if err != nil {
		writeAccountProblem(c, http.StatusUnauthorized, "authentication_required", "Authentication required", "A valid account session is required.", nil)
		return AccountID{}, false
	}
	return accountID, true
}

func decodeProfileUpdate(c *gin.Context, accountID AccountID) (UpdateProfileRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(c.Request.Body).Decode(&raw); err != nil {
		return UpdateProfileRequest{}, &ProfileValidationError{Fields: []ProfileFieldError{{Field: "body", Reason: "must be valid JSON"}}}
	}

	req := UpdateProfileRequest{AccountID: accountID}
	var fields []ProfileFieldError
	for field, value := range raw {
		switch field {
		case "display_name":
			var displayName string
			if err := json.Unmarshal(value, &displayName); err != nil {
				fields = append(fields, ProfileFieldError{Field: "display_name", Reason: "must be a string"})
				continue
			}
			req.DisplayName = displayName
			req.DisplayNameSet = true
		case "metadata":
			req.Metadata = append(json.RawMessage(nil), value...)
			req.MetadataSet = true
		default:
			fields = append(fields, ProfileFieldError{Field: field, Reason: "is not supported"})
		}
	}
	if len(fields) > 0 {
		return UpdateProfileRequest{}, &ProfileValidationError{Fields: fields}
	}
	return req, nil
}

func writeAccountError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrInvalidProfile):
		var validationErr *ProfileValidationError
		var fields []httpx.ProblemField
		if errors.As(err, &validationErr) {
			fields = make([]httpx.ProblemField, 0, len(validationErr.Fields))
			for _, field := range validationErr.Fields {
				fields = append(fields, httpx.ProblemField{Name: field.Field, Reason: field.Reason})
			}
		}
		writeAccountProblem(c, http.StatusBadRequest, "invalid_profile", "Invalid profile", "The profile update is invalid.", fields)
	case errors.Is(err, ErrProfileNotFound):
		writeAccountProblem(c, http.StatusNotFound, "profile_not_found", "Profile not found", "The profile was not found.", nil)
	case errors.Is(err, ErrInvalidCredential):
		writeAccountProblem(c, http.StatusBadRequest, "invalid_credential", "Invalid credential", "The credential request is invalid.", nil)
	case errors.Is(err, ErrCredentialNotFound):
		writeAccountProblem(c, http.StatusNotFound, "credential_not_found", "Credential not found", "The credential was not found.", nil)
	case errors.Is(err, ErrLastCredential):
		writeAccountProblem(c, http.StatusConflict, "last_credential", "Last credential", "At least one active credential must remain on the account.", nil)
	case errors.Is(err, ErrCredentialReauthenticationRequired):
		writeAccountProblem(c, http.StatusForbidden, "reauthentication_required", "Reauthentication required", "Recent primary authentication is required for this credential change.", nil)
	default:
		writeAccountProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", nil)
	}
}

func writeAccountProblem(c *gin.Context, status int, code, title, detail string, fields []httpx.ProblemField) {
	httpx.WriteProblem(c, httpx.Problem{
		Type:    fmt.Sprintf("https://aether-auth.local/problems/%s", code),
		Title:   title,
		Status:  status,
		Code:    code,
		Detail:  detail,
		Fields:  fields,
		ErrorID: accountErrorID(code),
	})
}

func accountErrorID(code string) string {
	switch code {
	case "authentication_required":
		return "ACCOUNT-0001"
	case "invalid_profile":
		return "ACCOUNT-0002"
	case "profile_not_found":
		return "ACCOUNT-0003"
	case "invalid_credential", "invalid_credential_id":
		return "ACCOUNT-0004"
	case "credential_not_found":
		return "ACCOUNT-0005"
	case "last_credential":
		return "ACCOUNT-0006"
	case "reauthentication_required":
		return "ACCOUNT-0007"
	case "authentication_not_configured", "profile_not_configured", "credentials_not_configured":
		return "ACCOUNT-0008"
	default:
		return "ACCOUNT-0009"
	}
}
