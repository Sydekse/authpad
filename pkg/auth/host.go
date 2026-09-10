package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/middleware"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/google/uuid"
)

var (
	ErrNoSession   = errors.New("no session")
	ErrMFARequired = errors.New("mfa verification required")
	ErrEmailTaken  = service.ErrEmailTaken
)

type Identity struct {
	UserID               uuid.UUID
	SessionID            uuid.UUID
	Token                string
	MFAPending           bool
	ActiveOrganizationID *uuid.UUID
}

type CreateAccountRequest struct {
	Email         string
	Password      string
	Profile       map[string]any
	EmailVerified bool
	SkipSession   bool
}

type CreateAccountResult = service.CreateAccountResult

func (a *Auth) IdentityFromRequest(r *http.Request) (*Identity, error) {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return nil, errors.New("auth is not initialized")
	}
	token := sessionTokenWithName(r, cookieName(a))
	if token == "" {
		return nil, nil
	}
	sess, err := a.srv.AuthSvc.GetSessionByToken(r.Context(), token)
	if errors.Is(err, service.ErrSessionNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, nil
	}
	return &Identity{
		UserID:               sess.UserID,
		SessionID:            sess.ID,
		Token:                token,
		MFAPending:           sess.MFAPending,
		ActiveOrganizationID: sess.ActiveOrganizationID,
	}, nil
}

// writeHostError emits the same {"error":{"code","message"}} envelope the
// mounted handlers use. http.Error is unusable here because it forces
// Content-Type: text/plain.
func writeHostError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func (a *Auth) RequireUser(w http.ResponseWriter, r *http.Request) (*Identity, bool) {
	id, err := a.IdentityFromRequest(r)
	if err != nil {
		writeHostError(w, http.StatusInternalServerError, "SESSION_LOOKUP_FAILED", "Could not verify session")
		return nil, false
	}
	if id == nil || id.UserID == uuid.Nil {
		writeHostError(w, http.StatusUnauthorized, "NO_SESSION", "Authentication required")
		return nil, false
	}
	if id.MFAPending {
		writeHostError(w, http.StatusForbidden, "MFA_REQUIRED", "MFA verification required")
		return nil, false
	}
	return id, true
}

func (a *Auth) ValidBearerToken(r *http.Request, token string) bool {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return false
	}
	sess, err := a.srv.AuthSvc.GetSessionByToken(r.Context(), token)
	return err == nil && sess != nil && !sess.MFAPending
}

func (a *Auth) SetSessionCookie(w http.ResponseWriter, token string, ttl ...time.Duration) {
	cfg := a.config()
	maxAge := int(cfg.Session.TTL.Seconds())
	if len(ttl) > 0 && ttl[0] > 0 {
		maxAge = int(ttl[0].Seconds())
	}
	if maxAge <= 0 {
		maxAge = 7 * 24 * 3600
	}
	name := cfg.Session.CookieName
	if name == "" {
		name = "session"
	}
	c := &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.Session.CookieSecure,
	}
	if cfg.Session.CookieDomain != "" {
		c.Domain = cfg.Session.CookieDomain
	}
	http.SetCookie(w, c)
}

func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	cfg := a.config()
	name := cfg.Session.CookieName
	if name == "" {
		name = "session"
	}
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.Session.CookieSecure,
	}
	if cfg.Session.CookieDomain != "" {
		c.Domain = cfg.Session.CookieDomain
	}
	http.SetCookie(w, c)
}

func (a *Auth) IssueCSRFToken(w http.ResponseWriter, r *http.Request) {
	token := middleware.EnsureCSRFCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"csrf_token":"` + token + `"}`))
}

func (a *Auth) CreateAccount(ctx context.Context, req CreateAccountRequest, ip, ua string) (*CreateAccountResult, error) {
	if a.srv == nil || a.srv.AccountSvc == nil {
		return nil, errors.New("account service is not initialized")
	}
	return a.srv.AccountSvc.CreateAccount(ctx, service.CreateAccountRequest{
		Email:         req.Email,
		Password:      req.Password,
		Profile:       req.Profile,
		EmailVerified: req.EmailVerified,
		SkipSession:   req.SkipSession,
	}, ip, ua)
}

func (a *Auth) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID) (string, error) {
	if a.srv == nil || a.srv.AuthSvc == nil {
		return "", errors.New("auth is not initialized")
	}
	return a.srv.AuthSvc.CreateEmailVerificationToken(ctx, userID)
}

func (a *Auth) AssignRole(ctx context.Context, userID uuid.UUID, role string) error {
	if a.srv == nil || a.srv.IdPSvc == nil {
		return errors.New("idp is not enabled")
	}
	return a.srv.IdPSvc.AssignRoleByName(ctx, userID, role)
}

func (a *Auth) HashPassword(password string) (string, error) {
	if a.srv == nil || a.srv.Password == nil {
		return "", errors.New("password service is not initialized")
	}
	return a.srv.Password.Hash(password)
}

func HashToken(token string) string { return security.HashToken(token) }

func GenerateOpaqueToken() (string, error) { return security.GenerateOpaqueToken() }

func RedirectAllowed(cfg *Config, raw string) bool {
	return security.RedirectAllowed(cfg, raw)
}

func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return middleware.CORS(allowedOrigins)
}

func CSRF(cfg middleware.CSRFConfig) func(http.Handler) http.Handler {
	return middleware.CSRF(cfg)
}

type CSRFConfig = middleware.CSRFConfig

func (a *Auth) config() Config {
	if a != nil && a.srv != nil && a.srv.AuthHandlersCfg() != nil {
		return *a.srv.AuthHandlersCfg()
	}
	return Config{}
}

func cookieName(a *Auth) string {
	n := a.config().Session.CookieName
	if n == "" {
		return "session"
	}
	return n
}

func sessionTokenWithName(r *http.Request, cookieName string) string {
	if c, _ := r.Cookie(cookieName); c != nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
