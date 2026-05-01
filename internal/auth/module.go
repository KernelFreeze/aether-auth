package auth

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the auth orchestrator feature.
type Deps struct{}

// Module owns login and auth-method HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the auth feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts auth routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
