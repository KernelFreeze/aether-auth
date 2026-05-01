package keys_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/keys"
	"github.com/KernelFreeze/aether-auth/internal/platform/queue"
)

func TestNewRotationTaskIncludesOverlapWindow(t *testing.T) {
	task, err := keys.NewRotationTask(config.PASETOConfig{
		OverlapWindow: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewRotationTask() error = %v", err)
	}
	if task.Type() != queue.TypeKeyRotation {
		t.Fatalf("task type = %q, want %q", task.Type(), queue.TypeKeyRotation)
	}

	var payload keys.RotationPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		t.Fatalf("payload JSON error = %v", err)
	}
	if payload.OverlapWindow != "2h0m0s" {
		t.Fatalf("overlap_window = %q, want 2h0m0s", payload.OverlapWindow)
	}
}

func TestRegisterRotationSchedule(t *testing.T) {
	scheduler := &recordingScheduler{}
	entryID, err := keys.RegisterRotationSchedule(scheduler, config.PASETOConfig{
		RotationInterval: time.Hour,
		OverlapWindow:    30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("RegisterRotationSchedule() error = %v", err)
	}
	if entryID != "entry-1" {
		t.Fatalf("entry ID = %q, want entry-1", entryID)
	}
	if scheduler.spec != "@every 1h0m0s" {
		t.Fatalf("cron spec = %q, want @every 1h0m0s", scheduler.spec)
	}
	if scheduler.task == nil || scheduler.task.Type() != queue.TypeKeyRotation {
		t.Fatalf("task = %#v, want key rotation task", scheduler.task)
	}
	if len(scheduler.opts) != 4 {
		t.Fatalf("option count = %d, want 4", len(scheduler.opts))
	}
}

func TestRotationCronSpecUsesDefaultInterval(t *testing.T) {
	if got := keys.RotationCronSpec(config.PASETOConfig{}); got != "@every 2160h0m0s" {
		t.Fatalf("RotationCronSpec() = %q, want @every 2160h0m0s", got)
	}
}

type recordingScheduler struct {
	spec string
	task *asynq.Task
	opts []asynq.Option
}

func (s *recordingScheduler) Register(cronspec string, task *asynq.Task, opts ...asynq.Option) (string, error) {
	s.spec = cronspec
	s.task = task
	s.opts = opts
	return "entry-1", nil
}
