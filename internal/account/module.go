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

// Module owns account and credential HTTP handlers.
type Module struct {
	profiles    profileManager
	credentials credentialManager
}

type profileManager interface {
	GetProfile(ctx context.Context, accountID AccountID) (AccountProfile, error)
	UpdateProfile(ctx context.Context, req UpdateProfileRequest) (AccountProfile, error)
}

type credentialManager interface {
	ListCredentials(ctx context.Context, accountID AccountID) ([]Credential, error)
	RemoveCredential(ctx context.Context, req RemoveCredentialRequest) (Credential, error)
}

var _ httpapi.Module = (*Module)(nil)

// New builds the account feature module.
func New(deps Deps) *Module {
	return &Module{
		profiles:    deps.Profiles,
		credentials: deps.Credentials,
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
}
