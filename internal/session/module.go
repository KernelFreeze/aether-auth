package session

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
)

// Deps holds the dependencies for the session feature.
type Deps struct {
	Refresher Refresher
}

// Refresher is the refresh-token rotation surface used by HTTP handlers.
type Refresher interface {
	RefreshSession(context.Context, RefreshSessionRequest) (RefreshSessionResult, error)
}

// Module owns session lifecycle HTTP handlers.
type Module struct {
	refresher Refresher
}

var _ httpapi.Module = (*Module)(nil)

// New builds the session feature module.
func New(deps Deps) *Module {
	return &Module{refresher: deps.Refresher}
}

// RegisterRoutes mounts session routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(r gin.IRouter, _ httpapi.Middlewares) {
	r.POST("/refresh", m.handleRefresh)
}
