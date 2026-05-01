package httpx

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// ProblemMediaType is the response content type for RFC 9457 problem
	// details.
	ProblemMediaType = "application/problem+json"
	defaultProblem   = "about:blank"

	// ProblemTypeInvalidCredentials identifies the generic login failure.
	ProblemTypeInvalidCredentials = "https://aether-auth.local/problems/invalid-credentials"
	// ProblemTypeResetRequestAccepted identifies the generic reset response.
	ProblemTypeResetRequestAccepted = "https://aether-auth.local/problems/reset-request-accepted"

	// ErrorIDLoginGeneric is the stable public ID for login failures.
	ErrorIDLoginGeneric = "AUTH-LOGIN-0001"
	// ErrorIDPasswordReset is the stable public ID for reset request responses.
	ErrorIDPasswordReset = "AUTH-RESET-0001"
)

// Problem is a problem+json response body.
type Problem struct {
	Type     string         `json:"type"`
	Title    string         `json:"title"`
	Status   int            `json:"status"`
	Code     string         `json:"code,omitempty"`
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

// AuthFailureProblem returns the public login failure used for credential
// misses, locked accounts, and other account-sensitive login failures.
func AuthFailureProblem() Problem {
	return Problem{
		Type:    ProblemTypeInvalidCredentials,
		Title:   "Invalid credentials",
		Status:  http.StatusUnauthorized,
		Code:    "invalid_credentials",
		Detail:  "The username or password is incorrect.",
		ErrorID: ErrorIDLoginGeneric,
	}
}

// WriteAuthFailure writes the generic login failure response.
func WriteAuthFailure(c *gin.Context) {
	WriteProblem(c, AuthFailureProblem())
}

// PasswordResetAcceptedProblem returns the generic reset response used when the
// caller must not learn whether an account exists.
func PasswordResetAcceptedProblem() Problem {
	return Problem{
		Type:    ProblemTypeResetRequestAccepted,
		Title:   "Reset request accepted",
		Status:  http.StatusAccepted,
		Code:    "reset_request_accepted",
		Detail:  "If the account can be reset, instructions will be sent.",
		ErrorID: ErrorIDPasswordReset,
	}
}

// WritePasswordResetAccepted writes the generic password-reset response.
func WritePasswordResetAccepted(c *gin.Context) {
	WriteProblem(c, PasswordResetAcceptedProblem())
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

// Sleeper waits for d or returns when ctx is canceled.
type Sleeper func(ctx context.Context, d time.Duration) error

// TimingEqualizer pads account-sensitive flows to a minimum duration.
type TimingEqualizer struct {
	MinDuration time.Duration
	Now         func() time.Time
	Sleep       Sleeper
}

// Started returns the start time to pass to Wait.
func (e TimingEqualizer) Started() time.Time {
	return e.now()()
}

// Wait sleeps until MinDuration has elapsed since started.
func (e TimingEqualizer) Wait(ctx context.Context, started time.Time) error {
	if e.MinDuration <= 0 {
		return nil
	}
	elapsed := e.now()().Sub(started)
	remaining := e.MinDuration - elapsed
	if remaining <= 0 {
		return nil
	}
	return e.sleeper()(ctx, remaining)
}

func (e TimingEqualizer) now() func() time.Time {
	if e.Now != nil {
		return e.Now
	}
	return time.Now
}

func (e TimingEqualizer) sleeper() Sleeper {
	if e.Sleep != nil {
		return e.Sleep
	}
	return SleepContext
}

// SleepContext sleeps for d or returns ctx.Err if the context is canceled.
func SleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
