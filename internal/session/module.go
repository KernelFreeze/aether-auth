package session

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the session feature.
type Deps struct{}

// Module owns session lifecycle HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the session feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts session routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
