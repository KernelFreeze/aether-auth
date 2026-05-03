package account

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the account feature.
type Deps struct {
	Profiles    ProfileManager
	Credentials CredentialManager
	Sessions    AccountSessionManager
	TOTP        TOTPManager
}

// ProfileManager is the profile service surface used by HTTP handlers.
type ProfileManager interface {
	GetProfile(ctx context.Context, accountID AccountID) (AccountProfile, error)
	UpdateProfile(ctx context.Context, req UpdateProfileRequest) (AccountProfile, error)
}

// CredentialManager is the credential service surface used by HTTP handlers.
type CredentialManager interface {
	ListCredentials(ctx context.Context, accountID AccountID) ([]Credential, error)
	RemoveCredential(ctx context.Context, req RemoveCredentialRequest) (Credential, error)
}

// AccountSessionManager is the account-owned session surface used by HTTP handlers.
type AccountSessionManager interface {
	ListAccountSessions(context.Context, AccountID) ([]AccountSession, error)
	RevokeAccountSession(context.Context, AccountID, SessionID) error
}

// TOTPManager owns TOTP enrollment and recovery-code regeneration for account
// settings routes.
type TOTPManager interface {
	EnrollTOTP(context.Context, TOTPEnrollmentRequest) (TOTPEnrollment, error)
	ConfirmTOTP(context.Context, TOTPConfirmRequest) (TOTPCredential, error)
	GenerateRecoveryCodes(context.Context, RecoveryCodeGenerateRequest) (GeneratedRecoveryCodes, error)
}

// Module owns account and credential HTTP handlers.
type Module struct {
	profiles    profileManager
	credentials credentialManager
	sessions    accountSessionManager
	totp        TOTPManager
}

type profileManager interface {
	GetProfile(ctx context.Context, accountID AccountID) (AccountProfile, error)
	UpdateProfile(ctx context.Context, req UpdateProfileRequest) (AccountProfile, error)
}

type credentialManager interface {
	ListCredentials(ctx context.Context, accountID AccountID) ([]Credential, error)
	RemoveCredential(ctx context.Context, req RemoveCredentialRequest) (Credential, error)
}

type accountSessionManager interface {
	ListAccountSessions(context.Context, AccountID) ([]AccountSession, error)
	RevokeAccountSession(context.Context, AccountID, SessionID) error
}

var _ httpapi.Module = (*Module)(nil)

// New builds the account feature module.
func New(deps Deps) *Module {
	return &Module{
		profiles:    deps.Profiles,
		credentials: deps.Credentials,
		sessions:    deps.Sessions,
		totp:        deps.TOTP,
	}
}

// RegisterRoutes mounts account routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(r gin.IRouter, mw httpapi.Middlewares) {
	auth := mw.Authenticate
	if auth == nil {
		auth = authenticationNotConfigured
	}

	protected := r.Group("")
	protected.Use(auth)
	protected.GET("/profile", m.handleGetProfile)
	protected.PATCH("/profile", m.handleUpdateProfile)
	protected.GET("/credentials", m.handleListCredentials)
	protected.DELETE("/credentials/:credential_id", m.handleRemoveCredential)
	protected.GET("/sessions", m.handleListSessions)
	protected.DELETE("/sessions/:id", m.handleRevokeSession)
	protected.POST("/mfa/totp/enroll", m.handleEnrollTOTP)
	protected.POST("/mfa/totp/confirm", m.handleConfirmTOTP)
	protected.DELETE("/mfa/totp/:credential_id", m.handleDisableTOTP)
	protected.POST("/mfa/recovery-codes/regenerate", m.handleRegenerateRecoveryCodes)
}
