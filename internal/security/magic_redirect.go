package security

import (
	"net/url"
	"strings"
)

// MagicLinkRedirectAllowed reports whether raw may be used as a post-sign-in
// redirect. raw must be an absolute http(s) URL whose scheme, host and port
// exactly equal one of the allowlist origins. Userinfo, backslashes, control
// characters, protocol-relative and non-http(s) URLs are always rejected.
func MagicLinkRedirectAllowed(allowlist []string, raw string) bool {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 2048 {
		return false
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || r == '\\' {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" {
		return false
	}
	origin, ok := originOf(u)
	if !ok {
		return false
	}
	for _, entry := range allowlist {
		a, err := url.Parse(strings.TrimSpace(entry))
		if err != nil || a.User != nil || (a.Path != "" && a.Path != "/") || a.RawQuery != "" || a.Fragment != "" {
			continue
		}
		if ao, ok := originOf(a); ok && ao == origin {
			return true
		}
	}
	return false
}

// originOf returns "scheme://host:port" with default ports made explicit.
func originOf(u *url.URL) (string, bool) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	return scheme + "://" + host + ":" + port, true
}

// NormalizeOrigin parses raw as a bare http(s) origin (no userinfo, path,
// query or fragment) and returns it as "scheme://host:port".
func NormalizeOrigin(raw string) (string, bool) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 300 {
		return "", false
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || r == '\\' {
			return "", false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return "", false
	}
	return originOf(u)
}

// OriginOfURL returns the normalized origin of an absolute http(s) URL.
func OriginOfURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return "", false
	}
	return originOf(u)
}
