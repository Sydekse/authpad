package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/middleware"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/Sydekse/authpad/pkg/apierror"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type MagicLinkHandlers struct {
	Links *service.MagicLinkService
	Auth  *service.AuthService
	MFA   *service.MFAService
	Audit *service.AuditService
	Orgs  *service.OrgService
	Cfg   *apptypes.AppConfig
}

type magicLinkRequestBody struct {
	Email      string `json:"email"`
	Tenant     string `json:"tenant"`
	RedirectTo string `json:"redirect_to"`
}

// Request always answers 202 with the same body once the JSON parses. All
// lookups, rate limiting and mail delivery happen after the response is decided.
func (h *MagicLinkHandlers) Request(w http.ResponseWriter, r *http.Request) {
	var req magicLinkRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	h.Links.Submit(service.MagicLinkRequest{
		Email:      req.Email,
		Tenant:     req.Tenant,
		RedirectTo: req.RedirectTo,
		IP:         parseIPFromRemote(r),
	})
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (h *MagicLinkHandlers) fail(w http.ResponseWriter, r *http.Request) {
	if u := strings.TrimSpace(h.Cfg.Pages.ErrorURL); u != "" {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		http.Redirect(w, r, u+sep+"error=invalid_link", http.StatusSeeOther)
		return
	}
	apierror.BadRequest(w, "INVALID_OR_EXPIRED_TOKEN", "This sign-in link is invalid or has expired")
}

func (h *MagicLinkHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	ip := parseIPFromRemote(r)
	ua := r.Header.Get("User-Agent")
	q := r.URL.Query()
	res, err := h.Links.Verify(r.Context(), q.Get("token"), q.Get("tenant"), ip, ua)
	if err != nil {
		h.fail(w, r)
		return
	}
	user := res.User

	if h.Cfg.MagicLink.CodeFlow && h.Links.CodeFlowReady() && h.destination(res) == "" {
		// Nowhere to send the code; the link is already spent.
		apierror.BadRequest(w, "NO_REDIRECT", "No redirect URL is configured for this sign-in")
		return
	}

	// From here on this mirrors Login.
	ttl := h.Cfg.Session.TTL
	token, sess, err := h.Auth.CreateSessionWithTTL(r.Context(), user.ID, ip, ua, ttl)
	if err != nil {
		log.Error().Err(err).Msg("magic link: create session failed")
		apierror.Internal(w, "LOGIN_FAILED", "Could not create session")
		return
	}
	if h.Orgs != nil {
		if m, _ := h.Orgs.Membership(r.Context(), res.Organization.ID, user.ID); m != nil && m.Status == "active" {
			_ = h.Orgs.SwitchActive(r.Context(), sess.ID, user.ID, res.Organization.ID)
		}
	}
	if !(h.Cfg.MagicLink.CodeFlow && h.Links.CodeFlowReady()) {
		middleware.EnsureCSRFCookie(w, r)
	}

	if h.MFA != nil {
		if has, err := h.MFA.UserHasMFA(r.Context(), user.ID); err == nil && has {
			if err := h.Auth.SetSessionMFAPending(r.Context(), sess.ID, true); err != nil {
				apierror.Internal(w, "LOGIN_FAILED", "Could not start MFA challenge")
				return
			}
			// The session cannot be used until /auth/mfa/challenge succeeds.
			h.complete(w, r, res, token, sess.ID, ttl, true)
			return
		}
	}

	if h.Audit != nil {
		h.Audit.LogAuth(r.Context(), &user.ID, "login.success", ip, ua, map[string]any{
			"method": "magic_link", "organization_id": res.Organization.ID.String(), "new_account": res.Created,
		})
	}
	if h.Cfg.Hooks.OnLogin != nil {
		if err := h.Cfg.Hooks.OnLogin(r.Context(), user.ID); err != nil {
			_ = h.Auth.RevokeSession(r.Context(), sess.ID)
			apierror.Internal(w, "LOGIN_HOOK_FAILED", "Login hook failed")
			return
		}
	}
	h.complete(w, r, res, token, sess.ID, ttl, false)
}

// destination is the redirect target: the allowlisted redirect_to, else the
// configured defaults.
func (h *MagicLinkHandlers) destination(res *service.MagicLinkVerified) string {
	dest := res.RedirectTo
	if dest == "" {
		dest = strings.TrimSpace(h.Cfg.MagicLink.DefaultRedirectURL)
	}
	if dest == "" {
		dest = strings.TrimSpace(h.Cfg.Pages.CallbackURL)
	}
	return dest
}

// complete hands the session over: as a cookie normally, or as a one-time code
// appended to the redirect URL in code-flow mode (no authpad cookie is set).
func (h *MagicLinkHandlers) complete(w http.ResponseWriter, r *http.Request, res *service.MagicLinkVerified, token string, sessionID uuid.UUID, ttl time.Duration, mfaRequired bool) {
	if h.Cfg.MagicLink.CodeFlow && h.Links.CodeFlowReady() {
		dest := h.destination(res)
		code, err := h.Links.CreateCode(r.Context(), sessionID, res.Organization.ID, dest)
		if err != nil {
			log.Error().Err(err).Msg("magic link: create code failed")
			_ = h.Auth.RevokeSession(r.Context(), sessionID)
			apierror.Internal(w, "LOGIN_FAILED", "Could not create sign-in code")
			return
		}
		http.Redirect(w, r, appendCode(dest, code), http.StatusSeeOther)
		return
	}
	setSessionCookie(w, token, h.Cfg, ttl)
	h.finish(w, r, res, mfaRequired)
}

// appendCode adds code to dest's query, keeping existing parameters and the fragment.
func appendCode(dest, code string) string {
	u, err := url.Parse(dest)
	if err != nil {
		return dest
	}
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += "code=" + url.QueryEscape(code)
	return u.String()
}

type magicExchangeBody struct {
	Code           string `json:"code"`
	RedirectOrigin string `json:"redirect_origin"`
}

// Exchange redeems a one-time code for the session token. Server-to-server only.
func (h *MagicLinkHandlers) Exchange(w http.ResponseWriter, r *http.Request) {
	secret := h.Cfg.MagicLink.ExchangeSecret
	if secret == "" || !h.Cfg.MagicLink.CodeFlow || !h.Links.CodeFlowReady() {
		apierror.NotFound(w, "NOT_FOUND", "Not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !h.Links.AllowExchange(r.Context(), parseIPFromRemote(r)) {
		apierror.WriteJSON(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests")
		return
	}
	// Hash both sides so the comparison is constant-time regardless of length.
	got := sha256.Sum256([]byte(r.Header.Get("X-Authpad-Exchange-Secret")))
	want := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		apierror.Unauthorized(w, "INVALID_EXCHANGE_SECRET", "Invalid exchange secret")
		return
	}
	var body magicExchangeBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	ex, err := h.Links.Exchange(r.Context(), body.Code, body.RedirectOrigin)
	if err != nil {
		apierror.BadRequest(w, "INVALID_CODE", "This code is invalid or has expired")
		return
	}
	if h.Audit != nil {
		h.Audit.LogAuth(r.Context(), &ex.User.ID, "magic_link.exchange", parseIPFromRemote(r), r.Header.Get("User-Agent"), map[string]any{
			"organization_id": ex.OrgID.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_token": ex.SessionToken,
		"expires_at":    ex.ExpiresAt.UTC().Format(time.RFC3339),
		"user":          map[string]string{"id": ex.User.ID.String(), "email": ex.User.Email},
		"org_id":        ex.OrgID.String(),
		"mfa_required":  ex.MFAPending,
	})
}

func (h *MagicLinkHandlers) finish(w http.ResponseWriter, r *http.Request, res *service.MagicLinkVerified, mfaRequired bool) {
	dest := h.destination(res)
	if dest != "" {
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"mfa_required": mfaRequired,
		"user":         UserInfo{ID: res.User.ID.String(), Email: res.User.Email, EmailVerified: true},
	})
}
