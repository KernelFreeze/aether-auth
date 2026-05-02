package passwordreset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hibiken/asynq"

	"github.com/KernelFreeze/aether-auth/internal/platform/queue"
)

// AsynqEmailQueue queues password-reset email tasks.
type AsynqEmailQueue struct {
	client *asynq.Client
}

var _ EmailQueue = (*AsynqEmailQueue)(nil)

// NewAsynqEmailQueue builds an email queue backed by Asynq.
func NewAsynqEmailQueue(client *asynq.Client) *AsynqEmailQueue {
	return &AsynqEmailQueue{client: client}
}

// EnqueuePasswordResetEmail queues a reset email task.
func (q *AsynqEmailQueue) EnqueuePasswordResetEmail(ctx context.Context, email ResetEmail) error {
	if q == nil || q.client == nil {
		return errors.New("passwordreset: email queue client is nil")
	}
	payload, err := json.Marshal(emailTaskPayload{
		Template:  "password_reset",
		To:        email.To,
		Subject:   "Reset your Aether Auth password",
		RequestID: email.RequestID,
		Data: map[string]string{
			"account_id": email.AccountID.String(),
			"reset_url":  email.ResetURL,
			"expires_at": email.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		return fmt.Errorf("passwordreset: marshal reset email task: %w", err)
	}

	task := asynq.NewTask(queue.TypeEmailSend, payload)
	if _, err := q.client.EnqueueContext(ctx, task, asynq.Queue("default")); err != nil {
		return fmt.Errorf("passwordreset: enqueue reset email: %w", err)
	}
	return nil
}

type emailTaskPayload struct {
	Template  string            `json:"template"`
	To        string            `json:"to"`
	Subject   string            `json:"subject"`
	RequestID string            `json:"request_id,omitempty"`
	Data      map[string]string `json:"data"`
}
