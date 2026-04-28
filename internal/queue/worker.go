// internal/queue/worker.go
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hibiken/asynq"
)

const (
	TypeEmailDelivery = "email:deliver"
	TypeDataExport    = "data:export"
)

type TaskHandler struct {
	emailService EmailService
	// Add other services needed for tasks
}

func NewTaskHandler(emailService EmailService) *TaskHandler {
	return &TaskHandler{
		emailService: emailService,
	}
}

func NewQueueClient(redisAddr string) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})
}

func StartWorkerServer(redisAddr string, handler *TaskHandler) {
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr},
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
		},
	)

	mux := asynq.NewServeMux()
	mux.HandleFunc(TypeEmailDelivery, handler.HandleEmailDeliveryTask)
	mux.HandleFunc(TypeDataExport, handler.HandleDataExportTask)

	if err := srv.Run(mux); err != nil {
		log.Fatalf("Could not run queue server: %v", err)
	}
}

// Task Handlers
func (h *TaskHandler) HandleEmailDeliveryTask(ctx context.Context, t *asynq.Task) error {
	var p EmailDeliveryPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v", err)
	}

	// Process the email delivery task
	return h.emailService.Send(p.To, p.Subject, p.Body)
}

func (h *TaskHandler) HandleDataExportTask(ctx context.Context, t *asynq.Task) error {
	var p DataExportPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %v", err)
	}

	// Process the data export task
	return nil
}

// Task Payloads
type EmailDeliveryPayload struct {
	To      string
	Subject string
	Body    string
}

type DataExportPayload struct {
	UserID    string
	Format    string
	Timestamp time.Time
}
