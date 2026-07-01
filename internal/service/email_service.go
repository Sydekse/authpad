package service

import (
	"fmt"
	"strings"

	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/resend/resend-go/v3"
)

// EmailService sends transactional emails.
type EmailService struct {
	cfg   apptypes.EmailConfig
	pages apptypes.PagesConfig
}

func NewEmailService(cfg apptypes.EmailConfig, pages apptypes.PagesConfig) *EmailService {
	return &EmailService{cfg: cfg, pages: pages}
}

func (s *EmailService) SendPasswordReset(to, resetURL string) error {
	subject := fmt.Sprintf("Reset your %s password", s.appName())
	body := fmt.Sprintf("Open this link to reset your password (valid for 5 minutes):\n%s", resetURL)
	return s.send(to, subject, body, resetURL, "Reset password")
}

func (s *EmailService) SendEmailVerification(to, verifyURL string) error {
	subject := fmt.Sprintf("Verify your %s email", s.appName())
	body := fmt.Sprintf("Open this link to verify your email:\n%s", verifyURL)
	return s.send(to, subject, body, verifyURL, "Verify email")
}

func (s *EmailService) send(to, subject, textBody, actionURL, actionLabel string) error {
	if s.cfg.ResendAPIKey == "" || s.cfg.ResendFrom == "" {
		return nil
	}
	client := resend.NewClient(s.cfg.ResendAPIKey)
	htmlBody := fmt.Sprintf(`<p>%s</p><p><a href="%s">%s</a></p>`, textBody, actionURL, actionLabel)
	_, err := client.Emails.Send(&resend.SendEmailRequest{
		From:    s.cfg.ResendFrom,
		To:      []string{to},
		Subject: subject,
		Html:    htmlBody,
		Text:    textBody,
	})
	return err
}

func (s *EmailService) appName() string {
	if s.cfg.AppName != "" {
		return s.cfg.AppName
	}
	if s.pages.AppName != "" {
		return s.pages.AppName
	}
	return "App"
}

func (s *EmailService) BuildResetURL(token string) string {
	base := strings.TrimSuffix(s.pages.ResetPasswordURL, "/")
	if base == "" {
		return "/reset-password?token=" + token
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + token
}

func (s *EmailService) BuildVerifyURL(token string) string {
	base := strings.TrimSuffix(s.pages.VerifyEmailURL, "/")
	if base == "" {
		return "/verify-email?token=" + token
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + token
}
