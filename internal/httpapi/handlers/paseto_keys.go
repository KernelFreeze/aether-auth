package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// PASETOKeys serves the JWKS-equivalent discovery document that resource
// servers fetch to verify v4.public access tokens. Returns an empty key set
// at scaffold time; populated once internal/platform/keys is implemented.
func PASETOKeys() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"keys": []any{}})
	}
}
