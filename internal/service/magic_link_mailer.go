package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/rs/zerolog/log"
)

const resendEmailsURL = "https://api.resend.com/emails"

// ResendMagicLinkMailer sends magic links through the Resend HTTP API.
type ResendMagicLinkMailer struct {
	APIKey  string
	From    string
	AppName string
	// Endpoint defaults to the Resend emails URL; tests point it at httptest.
	Endpoint string
	Client   *http.Client
}

func (m *ResendMagicLinkMailer) SendMagicLink(ctx context.Context, to, linkURL string) error {
	htmlBody, textBody := renderSydekMail(m.AppName, mailContent{
		Preview:     fmt.Sprintf("Your %s sign-in link", m.AppName),
		Eyebrow:     "Sign in",
		Title:       "Sign in to " + m.AppName,
		Intro:       "Use the button below to sign in. No password needed.",
		ActionURL:   linkURL,
		ActionLabel: "Sign in",
		Note:        "This link expires soon and works once. If you did not request it, you can ignore this email.",
	})
	payload, err := json.Marshal(map[string]any{
		"from":    m.From,
		"to":      []string{to},
		"subject": fmt.Sprintf("Your %s sign-in link", m.AppName),
		"html":    htmlBody,
		"text":    textBody,
	})
	if err != nil {
		return err
	}
	endpoint := m.Endpoint
	if endpoint == "" {
		endpoint = resendEmailsURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	client := m.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("resend request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("resend returned status %d", resp.StatusCode)
	}
	return nil
}

// DevMagicLinkMailer prints the link instead of sending it. Non-production only.
type DevMagicLinkMailer struct {
	Out io.Writer
}

func (m *DevMagicLinkMailer) SendMagicLink(_ context.Context, to, linkURL string) error {
	out := m.Out
	if out == nil {
		out = os.Stdout
	}
	_, err := fmt.Fprintf(out, "[magic-link] RESEND_API_KEY not set; sign-in link for %s: %s\n", to, linkURL)
	return err
}

// unconfiguredMagicLinkMailer is the production fallback with no API key. It
// never sees, and so never logs, the token.
type unconfiguredMagicLinkMailer struct{}

func (unconfiguredMagicLinkMailer) SendMagicLink(context.Context, string, string) error {
	return errors.New("magic link not sent: RESEND_API_KEY is not configured")
}

// NewMagicLinkMailer picks the configured mailer: a host override, Resend when
// a key is set, the stdout dev mailer outside production, otherwise one that
// always errors.
func NewMagicLinkMailer(cfg *apptypes.AppConfig) apptypes.MagicLinkMailer {
	if cfg.MagicLink.Mailer != nil {
		return cfg.MagicLink.Mailer
	}
	if cfg.Email.ResendAPIKey != "" {
		from := cfg.MagicLink.From
		if from == "" {
			from = cfg.Email.ResendFrom
		}
		app := cfg.Email.AppName
		if app == "" {
			app = cfg.Pages.AppName
		}
		if app == "" {
			app = "Auth"
		}
		return &ResendMagicLinkMailer{APIKey: cfg.Email.ResendAPIKey, From: from, AppName: app}
	}
	if cfg.Env != "production" {
		return &DevMagicLinkMailer{}
	}
	log.Error().Msg("magic link: RESEND_API_KEY is empty in production; links will not be sent")
	return unconfiguredMagicLinkMailer{}
}
