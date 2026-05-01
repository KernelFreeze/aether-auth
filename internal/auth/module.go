package auth

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/account"
	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the auth orchestrator feature.
type Deps struct {
	Registration RegistrationManager
	Login        LoginManager
	Sessions     SessionIssuer
}

// RegistrationManager is the public account-registration surface used by the
// auth HTTP module.
type RegistrationManager interface {
	Register(context.Context, account.RegistrationRequest) (account.RegistrationResult, error)
}

// LoginManager is the public login surface used by auth HTTP handlers.
type LoginManager interface {
	Login(context.Context, LoginRequest) (AuthResult, error)
}

// Module owns login and auth-method HTTP handlers.
type Module struct {
	registration RegistrationManager
	login        LoginManager
	sessions     SessionIssuer
}

var _ httpapi.Module = (*Module)(nil)

// New builds the auth feature module.
func New(deps Deps) *Module {
	return &Module{
		registration: deps.Registration,
		login:        deps.Login,
		sessions:     deps.Sessions,
	}
}

// RegisterRoutes mounts auth routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(r gin.IRouter, _ httpapi.Middlewares) {
	r.POST("/register", m.handleRegister)
	r.POST("/login", m.handleLogin)
}
