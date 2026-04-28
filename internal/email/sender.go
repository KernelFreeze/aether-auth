// internal/email/sender.go
package email

import (
	"bytes"
	"fmt"
	"html/template"

	"gopkg.in/gomail.v2"
)

type EmailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type EmailService struct {
	config    EmailConfig
	dialer    *gomail.Dialer
	templates *template.Template
}

func NewEmailService(config EmailConfig) (*EmailService, error) {
	// Load email templates
	templates, err := template.ParseGlob("internal/email/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to load email templates: %w", err)
	}

	dialer := gomail.NewDialer(
		config.Host,
		config.Port,
		config.Username,
		config.Password,
	)

	return &EmailService{
		config:    config,
		dialer:    dialer,
		templates: templates,
	}, nil
}

func (s *EmailService) SendEmail(to []string, subject string, templateName string, data interface{}) error {
	var body bytes.Buffer
	if err := s.templates.ExecuteTemplate(&body, templateName, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	m := gomail.NewMessage()
	m.SetHeader("From", s.config.From)
	m.SetHeader("To", to...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body.String())

	if err := s.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
