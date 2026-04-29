package mailer

import (
	"context"
	"errors"
	"fmt"

	"github.com/wneessen/go-mail"

	"github.com/KernelFreeze/aether-auth/internal/platform/config"
	"github.com/KernelFreeze/aether-auth/internal/platform/secrets"
)

// Mailer sends transactional email through an SMTP relay. Templates are
// rendered by the caller; this type only owns transport.
type Mailer struct {
	client *mail.Client
	from   string
}

// New builds a Mailer from the project's MailerConfig.
func New(ctx context.Context, cfg config.MailerConfig, sec secrets.Provider) (*Mailer, error) {
	opts := []mail.Option{
		mail.WithPort(cfg.Port),
		mail.WithUsername(cfg.Username),
	}
	if cfg.StartTLS {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	}

	pw, err := sec.Resolve(ctx, cfg.PasswordRef)
	switch {
	case err == nil:
		opts = append(opts, mail.WithPassword(string(pw)))
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthPlain))
	case errors.Is(err, secrets.ErrNotFound):
		// no auth — fine for local Mailpit / MailHog
	default:
		return nil, fmt.Errorf("mailer: resolve password: %w", err)
	}

	client, err := mail.NewClient(cfg.Host, opts...)
	if err != nil {
		return nil, fmt.Errorf("mailer: build client: %w", err)
	}
	return &Mailer{client: client, from: cfg.From}, nil
}

// Close releases the underlying SMTP client.
func (m *Mailer) Close() error {
	if m == nil || m.client == nil {
		return nil
	}
	return m.client.Close()
}

// From returns the configured From address.
func (m *Mailer) From() string { return m.from }

// Client returns the underlying go-mail client. Exposed so feature packages
// can compose messages without the mailer having to know about each template.
func (m *Mailer) Client() *mail.Client { return m.client }
