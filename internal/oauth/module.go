package oauth

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the OAuth feature.
type Deps struct{}

// Module owns OAuth authorization-server HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the OAuth feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts OAuth routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
