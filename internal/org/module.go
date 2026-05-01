package org

import (
	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the organization feature.
type Deps struct{}

// Module owns organization, membership, and invitation HTTP handlers.
type Module struct{}

var _ httpapi.Module = (*Module)(nil)

// New builds the organization feature module.
func New(deps Deps) *Module {
	return &Module{}
}

// RegisterRoutes mounts organization routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(gin.IRouter, httpapi.Middlewares) {}
