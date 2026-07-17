package service

import (
	"fmt"
	"strings"

	"github.com/auth-project/authpad/internal/apptypes"
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
	htmlBody, textBody := renderSydekMail(s.appName(), mailContent{
		Preview:     fmt.Sprintf("Reset your %s password", s.appName()),
		Eyebrow:     "Security",
		Title:       "Reset your password",
		Intro:       fmt.Sprintf("We received a request to reset the password for your %s account. Use the button below to choose a new one.", s.appName()),
		ActionURL:   resetURL,
		ActionLabel: "Reset password",
		Note:        "This link expires in 5 minutes. If you did not request a reset, you can ignore this email.",
	})
	return s.send(to, fmt.Sprintf("Reset your %s password", s.appName()), htmlBody, textBody)
}

func (s *EmailService) SendEmailVerification(to, verifyURL string) error {
	htmlBody, textBody := renderSydekMail(s.appName(), mailContent{
		Preview:     fmt.Sprintf("Verify your email for %s", s.appName()),
		Eyebrow:     "Email verification",
		Title:       "Confirm your email address",
		Intro:       fmt.Sprintf("Thanks for creating a %s account. Confirm your email to activate it and sign in.", s.appName()),
		ActionURL:   verifyURL,
		ActionLabel: "Verify email",
		Note:        "This link expires in 24 hours. If you did not create an account, you can ignore this email.",
	})
	return s.send(to, fmt.Sprintf("Verify your %s email", s.appName()), htmlBody, textBody)
}

func (s *EmailService) send(to, subject, htmlBody, textBody string) error {
	if s.cfg.ResendAPIKey == "" || s.cfg.ResendFrom == "" {
		return nil
	}
	client := resend.NewClient(s.cfg.ResendAPIKey)
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
	return "Sydek Auth"
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
