// internal/middleware/logger.go
package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.Request.URL.Path

		// You can replace this with your preferred logging solution
		fmt.Printf("[%d] %s %s - %v\n", status, method, path, latency)
	}
}
