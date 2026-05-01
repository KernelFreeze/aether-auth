package keys

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/queue"
)

const (
	// DefaultRotationInterval matches the production default in config.
	DefaultRotationInterval = 90 * 24 * time.Hour
	// DefaultOverlapWindow keeps old public keys long enough for issued access
	// tokens and clock skew to drain.
	DefaultOverlapWindow = 14 * 24 * time.Hour
	rotationTimeout      = 30 * time.Second
)

// Scheduler is the Asynq scheduler surface used by key rotation registration.
type Scheduler interface {
	Register(cronspec string, task *asynq.Task, opts ...asynq.Option) (string, error)
}

// RotationPayload records the retention policy used by a key rotation task.
type RotationPayload struct {
	OverlapWindow string `json:"overlap_window"`
}

// NewRotationTask builds the queue task that reloads externally rotated
// PASETO secrets and prunes expired verification keys.
func NewRotationTask(cfg config.PASETOConfig) (*asynq.Task, error) {
	payload, err := json.Marshal(RotationPayload{
		OverlapWindow: effectiveOverlapWindow(cfg).String(),
	})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(queue.TypeKeyRotation, payload), nil
}

// RotationCronSpec returns the scheduler expression for key rotation.
func RotationCronSpec(cfg config.PASETOConfig) string {
	return fmt.Sprintf("@every %s", effectiveRotationInterval(cfg))
}

// RegisterRotationSchedule registers the periodic key rotation task.
func RegisterRotationSchedule(s Scheduler, cfg config.PASETOConfig) (string, error) {
	task, err := NewRotationTask(cfg)
	if err != nil {
		return "", err
	}
	return s.Register(
		RotationCronSpec(cfg),
		task,
		asynq.Queue("critical"),
		asynq.MaxRetry(3),
		asynq.Timeout(rotationTimeout),
		asynq.Unique(effectiveRotationInterval(cfg)/2),
	)
}

func effectiveRotationInterval(cfg config.PASETOConfig) time.Duration {
	if cfg.RotationInterval > 0 {
		return cfg.RotationInterval
	}
	return DefaultRotationInterval
}

func effectiveOverlapWindow(cfg config.PASETOConfig) time.Duration {
	if cfg.OverlapWindow > 0 {
		return cfg.OverlapWindow
	}
	return DefaultOverlapWindow
}
