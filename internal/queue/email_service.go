// internal/queue/email_service.go
package queue

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

// EmailService defines the interface for sending emails
type EmailService interface {
	Send(to string, subject string, body string) error
}

// SMTPEmailService implements EmailService using SMTP
type SMTPEmailService struct {
	dialer *gomail.Dialer
	from   string
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func NewSMTPEmailService(config SMTPConfig) *SMTPEmailService {
	dialer := gomail.NewDialer(
		config.Host,
		config.Port,
		config.Username,
		config.Password,
	)

	return &SMTPEmailService{
		dialer: dialer,
		from:   config.From,
	}
}

func (s *SMTPEmailService) Send(to string, subject string, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := s.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// MockEmailService implements EmailService for testing
type MockEmailService struct {
	SentEmails []MockEmail
}

type MockEmail struct {
	To      string
	Subject string
	Body    string
}

func NewMockEmailService() *MockEmailService {
	return &MockEmailService{
		SentEmails: make([]MockEmail, 0),
	}
}

func (s *MockEmailService) Send(to string, subject string, body string) error {
	s.SentEmails = append(s.SentEmails, MockEmail{
		To:      to,
		Subject: subject,
		Body:    body,
	})
	return nil
}
