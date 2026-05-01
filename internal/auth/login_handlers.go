package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/httpx"
)

const (
	errorIDLoginInvalid       ErrorID = "AUTH-LOGIN-0002"
	errorIDLoginNotConfigured ErrorID = "AUTH-LOGIN-0003"
	errorIDSessionMissing     ErrorID = "AUTH-LOGIN-0004"
)

func (m *Module) handleLogin(c *gin.Context) {
	if m.login == nil {
		writeAuthProblem(c, http.StatusNotImplemented, "login_not_configured", "Login not configured", "Login is not wired.", nil, errorIDLoginNotConfigured)
		return
	}

	req, err := decodeLogin(c)
	if err != nil {
		writeLoginError(c, err)
		return
	}

	result, err := m.login.Login(c.Request.Context(), req)
	if err != nil {
		writeLoginError(c, err)
		return
	}
	m.writeLoginSuccess(c, req, result)
}

type loginRequestBody struct {
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Status         string                  `json:"status"`
	Session        *loginSessionResponse   `json:"session,omitempty"`
	PartialSession *partialSessionResponse `json:"partial_session,omitempty"`
}

type loginSessionResponse struct {
	ID           string    `json:"id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type partialSessionResponse struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func decodeLogin(c *gin.Context) (LoginRequest, error) {
	var body loginRequestBody
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return LoginRequest{}, NewServiceError(ErrorKindMalformedInput, "login body must be valid JSON", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return LoginRequest{}, NewServiceError(ErrorKindMalformedInput, "login body must contain one JSON object", nil)
	}

	kind, err := account.ParseCredentialKind(body.Kind)
	if err != nil {
		return LoginRequest{}, NewServiceError(ErrorKindMalformedInput, "login credential kind is invalid", err)
	}
	if kind != account.CredentialKindPassword {
		return LoginRequest{}, NewServiceError(ErrorKindMalformedInput, "login credential kind is not supported yet", nil)
	}

	return LoginRequest{
		Kind:            kind,
		Username:        body.Username,
		CredentialInput: body.Password,
		IP:              c.ClientIP(),
		UserAgent:       c.Request.UserAgent(),
		RequestID:       middleware.RequestID(c),
	}, nil
}

func (m *Module) writeLoginSuccess(c *gin.Context, req LoginRequest, result AuthResult) {
	if !result.Session.Issue {
		c.JSON(http.StatusOK, loginResponse{Status: "verified"})
		return
	}
	if m.sessions == nil {
		writeAuthProblem(c, http.StatusNotImplemented, "session_not_configured", "Session not configured", "Session issuance is not wired.", nil, errorIDSessionMissing)
		return
	}

	if result.Session.Partial {
		issued, err := m.sessions.IssuePartialSession(c.Request.Context(), PartialSessionIssueRequest{
			AccountID:       result.AccountID,
			VerifiedFactors: result.VerifiedFactors,
			TTL:             time.Until(result.Session.ExpiresAt),
			Now:             time.Now(),
		})
		if err != nil {
			writeLoginError(c, err)
			return
		}
		c.JSON(http.StatusOK, loginResponse{
			Status: "mfa_required",
			PartialSession: &partialSessionResponse{
				ID:        issued.SessionID.String(),
				Token:     issued.Token,
				ExpiresAt: account.NormalizeTimestamp(issued.ExpiresAt),
			},
		})
		return
	}

	issued, err := m.sessions.IssueSession(c.Request.Context(), SessionIssueRequest{
		AccountID:       result.AccountID,
		VerifiedFactors: result.VerifiedFactors,
		Scopes:          result.Session.Scopes,
		Audience:        result.Session.Audience,
		IP:              req.IP,
		UserAgent:       req.UserAgent,
		Now:             time.Now(),
	})
	if err != nil {
		writeLoginError(c, err)
		return
	}
	c.JSON(http.StatusOK, loginResponse{
		Status: "authenticated",
		Session: &loginSessionResponse{
			ID:           issued.SessionID.String(),
			AccessToken:  issued.AccessToken,
			RefreshToken: issued.RefreshToken,
			ExpiresAt:    account.NormalizeTimestamp(issued.ExpiresAt),
		},
	})
}

func writeLoginError(c *gin.Context, err error) {
	if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrLockedAccount) || errors.Is(err, ErrPolicyDenied) {
		public := PublicErrorFor(err, PublicErrorContextLogin)
		httpx.WriteProblem(c, httpx.Problem{
			Type:    public.Type,
			Title:   public.Title,
			Status:  public.Status,
			Code:    public.Code,
			Detail:  public.Detail,
			ErrorID: string(public.ErrorID),
		})
		return
	}
	if errors.Is(err, ErrMalformedInput) {
		writeAuthProblem(c, http.StatusBadRequest, "invalid_login", "Invalid login", "The login request is invalid.", nil, errorIDLoginInvalid)
		return
	}
	writeAuthProblem(c, http.StatusInternalServerError, "internal_error", "Internal error", "The request could not be completed.", nil, ErrorIDInternal)
}
