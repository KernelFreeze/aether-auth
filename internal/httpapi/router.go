package httpapi

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/handlers"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
)

// Deps collects the wiring inputs the router needs. Feature modules will be
// attached to this struct as their packages come online.
type Deps struct {
	Config *config.Config
	Logger *zap.Logger
}

// NewRouter builds the project's Gin engine, applies the standard middleware
// stack, and mounts the cross-feature handlers. Feature modules call back
// into r.Group(...) once they're registered.
func NewRouter(d Deps) *gin.Engine {
	if d.Config.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(
		middleware.RequestIDMiddleware(),
		middleware.Recover(d.Logger),
		middleware.Logger(d.Logger),
		middleware.CORS(d.Config.CORS),
	)

	r.GET("/healthz", handlers.Health())
	r.GET("/.well-known/paseto-keys", handlers.PASETOKeys())

	return r
}
