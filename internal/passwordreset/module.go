package passwordreset

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/httpapi"
	"github.com/KernelFreeze/aether-auth/internal/ratelimit"
)

// Deps holds the dependencies for the password-reset feature.
type Deps struct {
	Requester Requester
}

// Requester is the public reset-request surface used by HTTP handlers.
type Requester interface {
	RequestReset(context.Context, RequestResetRequest) (RequestResetResult, error)
}

// Module owns password-reset request and confirmation HTTP handlers.
type Module struct {
	requester Requester
}

var _ httpapi.Module = (*Module)(nil)

// New builds the password-reset feature module.
func New(deps Deps) *Module {
	return &Module{requester: deps.Requester}
}

// RegisterRoutes mounts password-reset routes on the group assigned by httpapi.
func (m *Module) RegisterRoutes(r gin.IRouter, mw httpapi.Middlewares) {
	handlers := []gin.HandlerFunc{}
	if mw.RateLimit != nil {
		handlers = append(handlers, mw.RateLimit(ratelimit.WithEndpoint(resetRequestEndpoint)))
	}
	handlers = append(handlers, m.handleRequestReset)
	r.POST("/request", handlers...)
}
