package account

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the account feature.
type Deps struct{}

// Module owns account and credential HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the account feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts account routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
