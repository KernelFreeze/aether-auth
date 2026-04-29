package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Health returns a simple liveness probe handler. Wire under GET /healthz.
func Health() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
