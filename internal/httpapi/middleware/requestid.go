package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const requestIDHeader = "X-Request-Id"
const requestIDKey = "request_id"

// RequestIDMiddleware reads X-Request-Id from the incoming request, falling
// back to a fresh UUIDv7, and stamps it onto the context and the response
// header so downstream services can correlate logs.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if id == "" {
			if v, err := uuid.NewV7(); err == nil {
				id = v.String()
			} else {
				id = uuid.NewString()
			}
		}
		c.Set(requestIDKey, id)
		c.Writer.Header().Set(requestIDHeader, id)
		c.Next()
	}
}

// RequestID returns the request id stamped onto the context by
// RequestIDMiddleware, or the empty string if none was set.
func RequestID(c *gin.Context) string {
	v, ok := c.Get(requestIDKey)
	if !ok {
		return ""
	}
	id, _ := v.(string)
	return id
}
