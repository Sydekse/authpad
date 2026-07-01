package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/auth-project/goauth/internal/service"
	"github.com/auth-project/goauth/pkg/apierror"
	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/google/uuid"
)

type SessionResponse struct {
	User    UserInfo    `json:"user"`
	Session SessionInfo `json:"session"`
	Token   string      `json:"token,omitempty"`
}

type UserInfo struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	Name          string         `json:"name"`
	EmailVerified bool           `json:"email_verified"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type SessionInfo struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

func parseIPFromRemote(r *http.Request) string {
	raw := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		raw = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		if net.ParseIP(raw) != nil {
			return raw
		}
		return ""
	}
	return host
}

func getSessionToken(r *http.Request, cfg *apptypes.AppConfig) string {
	cookieName := cfg.Session.CookieName
	if cookieName == "" {
		cookieName = "session"
	}
	if c, _ := r.Cookie(cookieName); c != nil {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func setSessionCookie(w http.ResponseWriter, token string, cfg *apptypes.AppConfig) {
	maxAge := int(cfg.Session.TTL.Seconds())
	if maxAge <= 0 {
		maxAge = 7 * 24 * 3600
	}
	cookieName := cfg.Session.CookieName
	if cookieName == "" {
		cookieName = "session"
	}
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.Session.CookieSecure,
	}
	if cfg.Session.CookieDomain != "" {
		cookie.Domain = cfg.Session.CookieDomain
	}
	http.SetCookie(w, cookie)
}

func clearSessionCookie(w http.ResponseWriter, cfg *apptypes.AppConfig) {
	cookieName := cfg.Session.CookieName
	if cookieName == "" {
		cookieName = "session"
	}
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.Session.CookieSecure,
	}
	if cfg.Session.CookieDomain != "" {
		cookie.Domain = cfg.Session.CookieDomain
	}
	http.SetCookie(w, cookie)
}

func requireSession(w http.ResponseWriter, r *http.Request, authSvc *service.AuthService, cfg *apptypes.AppConfig) (*uuid.UUID, string, *service.AuthService, bool) {
	token := getSessionToken(r, cfg)
	if token == "" {
		apierror.UnauthorizedWithRedirect(w, cfg.Pages.SignInURL, r.URL.RequestURI(), "NO_SESSION", "No session token")
		return nil, "", authSvc, false
	}
	sess, err := authSvc.GetSessionByToken(r.Context(), token)
	if err != nil || sess == nil {
		apierror.UnauthorizedWithRedirect(w, cfg.Pages.SignInURL, r.URL.RequestURI(), "INVALID_SESSION", "Session expired or invalid")
		return nil, "", authSvc, false
	}
	if newToken, _, err := authSvc.RotateSession(r.Context(), sess); err == nil && newToken != "" {
		setSessionCookie(w, newToken, cfg)
		token = newToken
	}
	id := sess.UserID
	return &id, token, authSvc, true
}

func isServiceAuthorized(r *http.Request, cfg *apptypes.AppConfig) bool {
	key := strings.TrimSpace(r.Header.Get("X-Service-Key"))
	if key == "" {
		return false
	}
	for _, allowed := range cfg.Security.ServiceKeys {
		if key == allowed {
			return true
		}
	}
	return false
}

func canAccessUser(r *http.Request, cfg *apptypes.AppConfig, authSvc *service.AuthService, idpSvc *service.IdPService, target uuid.UUID) bool {
	if isServiceAuthorized(r, cfg) {
		return true
	}
	token := getSessionToken(r, cfg)
	if token == "" {
		return false
	}
	sess, err := authSvc.GetSessionByToken(r.Context(), token)
	if err != nil || sess == nil {
		return false
	}
	if sess.UserID == target {
		return true
	}
	if idpSvc == nil {
		return false
	}
	ok, _ := idpSvc.HasRole(r.Context(), sess.UserID, cfg.Security.AdminRoleName)
	return ok
}

func isAdmin(r *http.Request, cfg *apptypes.AppConfig, authSvc *service.AuthService, idpSvc *service.IdPService) (uuid.UUID, bool) {
	if isServiceAuthorized(r, cfg) {
		return uuid.Nil, true
	}
	token := getSessionToken(r, cfg)
	if token == "" {
		return uuid.Nil, false
	}
	sess, err := authSvc.GetSessionByToken(r.Context(), token)
	if err != nil || sess == nil || idpSvc == nil {
		return uuid.Nil, false
	}
	ok, _ := idpSvc.HasRole(r.Context(), sess.UserID, cfg.Security.AdminRoleName)
	return sess.UserID, ok
}

func appendRedirect(base, returnTo string) string {
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	if returnTo != "" {
		q := u.Query()
		q.Set("return_to", returnTo)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
