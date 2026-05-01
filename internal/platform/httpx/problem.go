package httpx

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// ProblemMediaType is the response content type for RFC 9457 problem
	// details.
	ProblemMediaType = "application/problem+json"
	defaultProblem   = "about:blank"
)

// Problem is a problem+json response body.
type Problem struct {
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Status   int            `json:"status"`
	Detail   string         `json:"detail,omitempty"`
	Instance string         `json:"instance,omitempty"`
	ErrorID  string         `json:"error_id,omitempty"`
	Fields   []ProblemField `json:"fields,omitempty"`
}

// ProblemField identifies one invalid request field.
type ProblemField struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// WriteProblem writes p as application/problem+json.
func WriteProblem(c *gin.Context, p Problem) {
	p = normalizeProblem(p)
	c.Header("Content-Type", ProblemMediaType)
	c.AbortWithStatusJSON(p.Status, p)
}

func normalizeProblem(p Problem) Problem {
	if p.Status == 0 {
		p.Status = http.StatusInternalServerError
	}
	if p.Type == "" {
		p.Type = defaultProblem
	}
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	return p
}
