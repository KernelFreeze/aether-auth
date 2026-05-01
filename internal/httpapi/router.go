package httpapi

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/KernelFreeze/aether-auth/internal/httpapi/handlers"
	"github.com/KernelFreeze/aether-auth/internal/httpapi/middleware"
	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/keys"
)

// Deps collects the wiring inputs the router needs. Feature modules will be
// attached to this struct as their packages come online.
type Deps struct {
	Config      *config.Config
	Logger      *zap.Logger
	PASETOKeys  keys.Source
	Modules     FeatureModules
	Middlewares Middlewares
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
	r.GET("/.well-known/paseto-keys", handlers.PASETOKeys(d.PASETOKeys))

	registerFeatureRoutes(r, d.Modules, d.Middlewares)

	return r
}

func registerFeatureRoutes(r *gin.Engine, modules FeatureModules, mw Middlewares) {
	mountModule(r, "/account", modules.Account, mw)
	mountModule(r, "/auth", modules.Auth, mw)
	mountModule(r, "/mfa", modules.MFA, mw)
	mountModule(r, "/oauth", modules.OAuth, mw)
	mountModule(r, "/org", modules.Organization, mw)
	mountModule(r, "/password-reset", modules.PasswordReset, mw)
	mountModule(r, "/session", modules.Session, mw)
}

func mountModule(r *gin.Engine, prefix string, module Module, mw Middlewares) {
	if module == nil {
		return
	}
	module.RegisterRoutes(r.Group(prefix), mw)
}
