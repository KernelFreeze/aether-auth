package passwordreset

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the password-reset feature.
type Deps struct{}

// Module owns password-reset request and confirmation HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the password-reset feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts password-reset routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
