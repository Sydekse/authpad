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
