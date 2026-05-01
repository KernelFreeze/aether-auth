package mfa

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the MFA feature.
type Deps struct{}

// Module owns MFA policy and challenge HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the MFA feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts MFA routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
