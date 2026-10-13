package apptypes

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func (c *AppConfig) Validate() error {
	if c.AuthDatabaseURL == "" {
		return errors.New("AuthDatabaseURL is required")
	}
	if c.Tenancy.Enabled && c.IdPDatabaseURL == "" {
		return errors.New("Tenancy.Enabled requires IdPDatabaseURL")
	}
	if c.Invitations.Enabled && c.IdPDatabaseURL == "" {
		return errors.New("Invitations.Enabled requires IdPDatabaseURL")
	}
	if c.MagicLink.Enabled {
		if !c.Tenancy.Enabled {
			return errors.New("MagicLink.Enabled requires Tenancy.Enabled")
		}
		u, err := url.Parse(strings.TrimSpace(c.MagicLink.BaseURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("MagicLink.BaseURL must be an absolute http(s) URL")
		}
		if c.MagicLink.CodeFlow {
			if c.MagicLink.ExchangeSecret == "" {
				return errors.New("MagicLink.CodeFlow requires MagicLink.ExchangeSecret")
			}
			if c.Env == "production" && len(c.MagicLink.ExchangeSecret) < 32 {
				return errors.New("MagicLink.ExchangeSecret must be at least 32 characters in production")
			}
		}
		if c.Env == "production" && c.MagicLink.Mailer == nil && c.Email.ResendAPIKey == "" {
			return errors.New("MagicLink requires RESEND_API_KEY (or a custom MagicLink.Mailer) in production")
		}
	}
	if c.Env != "production" {
		return nil
	}
	if c.Security.SessionSecret == "" {
		return errors.New("Security.SessionSecret must be set in production")
	}
	if len(c.Security.SessionSecret) < 32 {
		return errors.New("Security.SessionSecret must be at least 32 characters in production")
	}
	if strings.TrimSpace(c.Pages.ResetPasswordURL) == "" && strings.TrimSpace(c.Pages.SignInURL) == "" {
		return errors.New("Pages.ResetPasswordURL or Pages.SignInURL must be set in production")
	}
	for _, pageURL := range []string{c.Pages.SignInURL, c.Pages.ResetPasswordURL, c.Pages.VerifyEmailURL, c.Pages.CallbackURL} {
		if pageURL == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(pageURL))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("page URL must be absolute: %q", pageURL)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("page URL must use https in production: %q", pageURL)
		}
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || host == "127.0.0.1" {
			return fmt.Errorf("page URL must not point to localhost in production: %q", pageURL)
		}
	}
	return nil
}
