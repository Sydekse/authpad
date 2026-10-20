package service

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/resend/resend-go/v3"
)

// EmailService sends transactional emails.
type EmailService struct {
	cfg   apptypes.EmailConfig
	pages apptypes.PagesConfig
	// deliver replaces the Resend call in tests.
	deliver func(to, subject, htmlBody, textBody string) error
}

func NewEmailService(cfg apptypes.EmailConfig, pages apptypes.PagesConfig) *EmailService {
	return &EmailService{cfg: cfg, pages: pages}
}

// Lifetimes of the links in password reset and verification emails. The
// emails quote them, so they live here next to the copy.
const (
	PasswordResetTTL     = 5 * time.Minute
	EmailVerificationTTL = 24 * time.Hour
)

// lifetime words a fixed link lifetime, for example "5 minutes".
func lifetime(d time.Duration) string {
	now := time.Now()
	return expiresIn(now.Add(d), now)
}

func (s *EmailService) brand() mailBrand {
	return resolveBrand(s.appName(), s.cfg.Brand)
}

func (s *EmailService) SendPasswordReset(to, resetURL string) error {
	b := s.brand()
	subject := fmt.Sprintf("Reset your %s password", b.App)
	htmlBody, textBody := renderMail(b, mailContent{
		Preview:     fmt.Sprintf("Choose a new password with the link inside. It expires in %s.", lifetime(PasswordResetTTL)),
		Title:       "Reset your password",
		Intro:       fmt.Sprintf("We got a request to reset the password for your %s account. Use the link below to choose a new one.", b.App),
		ActionURL:   resetURL,
		ActionLabel: "Choose a new password",
		Note:        fmt.Sprintf("This link expires in %s. If you didn't ask to reset your password, you can ignore this email and nothing will change.", lifetime(PasswordResetTTL)),
	})
	return s.send(to, subject, htmlBody, textBody)
}

func (s *EmailService) SendEmailVerification(to, verifyURL string) error {
	b := s.brand()
	subject := fmt.Sprintf("Confirm your email for %s", b.App)
	htmlBody, textBody := renderMail(b, mailContent{
		Preview:     fmt.Sprintf("One click to finish setting up your %s account.", b.App),
		Title:       "Confirm your email address",
		Intro:       fmt.Sprintf("Thanks for signing up to %s. Confirm this is your email address and you're ready to sign in.", b.App),
		ActionURL:   verifyURL,
		ActionLabel: "Confirm email",
		Note:        fmt.Sprintf("This link expires in %s. If you didn't sign up, you can ignore this email.", lifetime(EmailVerificationTTL)),
	})
	return s.send(to, subject, htmlBody, textBody)
}

func (s *EmailService) send(to, subject, htmlBody, textBody string) error {
	if s.deliver != nil {
		return s.deliver(to, subject, htmlBody, textBody)
	}
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

// SendInvitation sends a platform invite. The role is not shown: role names
// are internal and mean nothing to the person invited.
func (s *EmailService) SendInvitation(to, inviteURL, role string) error {
	b := s.brand()
	subject := fmt.Sprintf("You've been invited to %s", b.App)
	htmlBody, textBody := renderMail(b, mailContent{
		Preview:     fmt.Sprintf("Accept your invite to set up your %s account.", b.App),
		Title:       fmt.Sprintf("You've been invited to %s", b.App),
		Intro:       "Use the link below to accept the invite and set up your account.",
		ActionURL:   inviteURL,
		ActionLabel: "Accept invite",
		Note:        "This link works once. If you weren't expecting this invite, you can ignore this email.",
	})
	return s.send(to, subject, htmlBody, textBody)
}

// SendOrgInvitation implements apptypes.OrgInvitationMailer.
func (s *EmailService) SendOrgInvitation(msg apptypes.OrgInvitationEmail) error {
	subject, htmlBody, textBody := renderOrgInvitation(s.brand(), msg, time.Now())
	return s.send(msg.To, subject, htmlBody, textBody)
}

// cleanOrgName keeps an organization name to one short line, so an org admin
// cannot write a paragraph into a branded subject and heading.
func cleanOrgName(name string) string {
	name = strings.Join(strings.FieldsFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if r := []rune(name); len(r) > maxOrgNameInEmail {
		name = strings.TrimSpace(string(r[:maxOrgNameInEmail-1])) + "\u2026"
	}
	return name
}

const maxOrgNameInEmail = 80

func renderOrgInvitation(b mailBrand, msg apptypes.OrgInvitationEmail, now time.Time) (subject, htmlBody, textBody string) {
	org := cleanOrgName(msg.OrgName)
	title := b.fill(b.InviteTitle, org)
	note := "This link works once."
	if left := expiresIn(msg.ExpiresAt, now); left != "" {
		note = fmt.Sprintf("This link works once and expires in %s.", left)
	}
	note += " If you weren't expecting this invite, you can ignore this email."
	htmlBody, textBody = renderMail(b, mailContent{
		Preview:     b.fill(b.InviteBody, org),
		Title:       title,
		Intro:       b.fill(b.InviteBody, org),
		ActionURL:   msg.InviteURL,
		ActionLabel: b.InviteButton,
		Note:        note,
	})
	return title, htmlBody, textBody
}

func (s *EmailService) appName() string {
	if s.cfg.AppName != "" {
		return s.cfg.AppName
	}
	if s.pages.AppName != "" {
		return s.pages.AppName
	}
	return "Auth"
}

func (s *EmailService) BuildResetURL(token string) string {
	return BuildResetURL(s.pages, token)
}

func (s *EmailService) BuildVerifyURL(token string) string {
	return BuildVerifyURL(s.pages, token)
}

func BuildResetURL(pages apptypes.PagesConfig, token string) string {
	return appendToken(pages.ResetPasswordURL, "/reset-password", token)
}

func BuildVerifyURL(pages apptypes.PagesConfig, token string) string {
	return appendToken(pages.VerifyEmailURL, "/verify-email", token)
}

func appendToken(base, fallback, token string) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		return fallback + "?token=" + url.QueryEscape(token)
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + url.QueryEscape(token)
}
