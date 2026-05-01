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
}

// RegistrationManager is the public account-registration surface used by the
// auth HTTP module.
type RegistrationManager interface {
	Register(context.Context, account.RegistrationRequest) (account.RegistrationResult, error)
}

// Module owns login and auth-method HTTP handlers.
type Module struct {
	registration RegistrationManager
}

var _ httpapi.Module = (*Module)(nil)

// New builds the auth feature module.
func New(deps Deps) *Module {
	return &Module{
		registration: deps.Registration,
	}
}

// RegisterRoutes mounts auth routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(r gin.IRouter, _ httpapi.Middlewares) {
	r.POST("/register", m.handleRegister)
}
