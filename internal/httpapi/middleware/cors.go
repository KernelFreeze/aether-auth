// Package middleware contains the HTTP middleware applied to API routes:
// CORS, request logging, request-id propagation, panic recovery, and (later)
// PASETO+scope auth, CSRF, and rate limiting.
package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
)

// CORS returns a Gin middleware enforcing the allowed origins/methods/headers
// from CORSConfig. A wildcard origin disables credential mode automatically.
func CORS(cfg config.CORSConfig) gin.HandlerFunc {
	allowedOrigins := cfg.AllowedOrigins
	allowedMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	wildcard := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			switch {
			case wildcard:
				c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			case originAllowed(origin, allowedOrigins):
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				c.Writer.Header().Set("Vary", "Origin")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		c.Writer.Header().Set("Access-Control-Allow-Headers", allowedHeaders)

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}
