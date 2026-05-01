package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/KernelFreeze/aether-auth/internal/platform/keys"
)

// PASETOKeys serves the JWKS-equivalent discovery document that resource
// servers fetch to verify v4.public access tokens.
func PASETOKeys(source keys.Source) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, keys.DiscoveryDocument(source))
	}
}
