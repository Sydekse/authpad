package security

import (
	"net/url"
	"testing"

	"github.com/Sydekse/authpad/internal/apptypes"
)

func TestRedirectAllowedExactAndCallback(t *testing.T) {
	cfg := &apptypes.AppConfig{
		OAuth: apptypes.OAuthConfig{AllowedRedirects: []string{"https://app.example.com/callback"}},
		Pages: apptypes.PagesConfig{CallbackURL: "https://app.example.com/oauth"},
	}
	if !RedirectAllowed(cfg, "https://app.example.com/callback") {
		t.Fatal("allowlisted URL should be accepted")
	}
	if !RedirectAllowed(cfg, "https://app.example.com/oauth") {
		t.Fatal("callback URL should be accepted")
	}
	if RedirectAllowed(cfg, "https://evil.example/phish") {
		t.Fatal("unknown URL should be rejected")
	}
	if RedirectAllowed(cfg, "/relative") {
		t.Fatal("relative URL should be rejected")
	}
	if RedirectAllowed(cfg, "") {
		t.Fatal("empty URL should be rejected")
	}
}

func TestRedirectAllowedOriginEntry(t *testing.T) {
	cfg := &apptypes.AppConfig{
		OAuth: apptypes.OAuthConfig{AllowedRedirects: []string{"https://app.example.com"}},
	}
	if !RedirectAllowed(cfg, "https://app.example.com/welcome") {
		t.Fatal("same-origin path should be accepted for origin allowlist entries")
	}
	if RedirectAllowed(cfg, "https://other.example.com/") {
		t.Fatal("different origin should be rejected")
	}
}

func TestRedirectAllowedHook(t *testing.T) {
	cfg := &apptypes.AppConfig{
		OAuth: apptypes.OAuthConfig{AllowedRedirects: []string{"https://never.example/"}},
		Hooks: apptypes.Hooks{
			ValidateReturnURL: func(raw string) bool {
				u, err := url.Parse(raw)
				return err == nil && u.Hostname() == "trusted.test"
			},
		},
	}
	if !RedirectAllowed(cfg, "https://trusted.test/x") {
		t.Fatal("hook should accept trusted.test")
	}
	if RedirectAllowed(cfg, "https://never.example/") {
		t.Fatal("hook should override allowlist")
	}
}
