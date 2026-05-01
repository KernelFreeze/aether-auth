package httpapi

import "github.com/gin-gonic/gin"

// Module is the route-registration contract for feature packages.
//
// Feature packages own their handlers and dependencies, but not their URL
// prefix. NewRouter gives each module the group it may mount into, which keeps
// the complete URL map in internal/httpapi/router.go.
type Module interface {
	RegisterRoutes(gin.IRouter, Middlewares)
}

// FeatureModules lists the route-owning feature modules known to the API.
// Nil entries are skipped so partially implemented features do not affect
// router construction.
type FeatureModules struct {
	Account       Module
	Auth          Module
	MFA           Module
	OAuth         Module
	Organization  Module
	PasswordReset Module
	Session       Module
}

// Middlewares carries route-specific middleware that feature modules may use.
// A nil field means that middleware is not wired yet.
type Middlewares struct {
	Authenticate  gin.HandlerFunc
	RequireScope  func(scopes ...string) gin.HandlerFunc
	CSRF          gin.HandlerFunc
	RateLimit     gin.HandlerFunc
	SecureHeaders gin.HandlerFunc
}
