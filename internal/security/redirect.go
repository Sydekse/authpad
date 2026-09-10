package security

import (
	"net/url"
	"strings"

	"github.com/Sydekse/authpad/internal/apptypes"
)

// RedirectAllowed reports whether raw is a safe post-auth return URL.
// If Hooks.ValidateReturnURL is set it is the authority after basic parsing.
// Otherwise the URL must exactly match AllowedRedirects or Pages.CallbackURL,
// or share origin with an allowlist entry that has an empty or "/" path.
func RedirectAllowed(cfg *apptypes.AppConfig, raw string) bool {
	if cfg == nil {
		return false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if cfg.Hooks.ValidateReturnURL != nil {
		return cfg.Hooks.ValidateReturnURL(raw)
	}
	allowed := append([]string{}, cfg.OAuth.AllowedRedirects...)
	if strings.TrimSpace(cfg.Pages.CallbackURL) != "" {
		allowed = append(allowed, cfg.Pages.CallbackURL)
	}
	for _, candidate := range allowed {
		if redirectMatch(strings.TrimSpace(candidate), u) {
			return true
		}
	}
	return false
}

func redirectMatch(allowed string, candidate *url.URL) bool {
	if allowed == "" || candidate == nil {
		return false
	}
	a, err := url.Parse(allowed)
	if err != nil || a.Scheme == "" || a.Host == "" {
		return false
	}
	if strings.EqualFold(a.String(), candidate.String()) {
		return true
	}
	if !strings.EqualFold(a.Scheme, candidate.Scheme) || !strings.EqualFold(a.Host, candidate.Host) {
		return false
	}
	ap := a.Path
	if ap == "" || ap == "/" {
		return true
	}
	return allowed == candidate.String()
}
