package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/middleware"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/Sydekse/authpad/pkg/apierror"
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
	middleware.EnsureCSRFCookie(w, r)

	if h.MFA != nil {
		if has, err := h.MFA.UserHasMFA(r.Context(), user.ID); err == nil && has {
			if err := h.Auth.SetSessionMFAPending(r.Context(), sess.ID, true); err != nil {
				apierror.Internal(w, "LOGIN_FAILED", "Could not start MFA challenge")
				return
			}
			// The session cannot be used until /auth/mfa/challenge succeeds.
			setSessionCookie(w, token, h.Cfg, ttl)
			h.finish(w, r, res, true)
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
	setSessionCookie(w, token, h.Cfg, ttl)
	h.finish(w, r, res, false)
}

func (h *MagicLinkHandlers) finish(w http.ResponseWriter, r *http.Request, res *service.MagicLinkVerified, mfaRequired bool) {
	dest := res.RedirectTo
	if dest == "" {
		dest = strings.TrimSpace(h.Cfg.MagicLink.DefaultRedirectURL)
	}
	if dest == "" {
		dest = strings.TrimSpace(h.Cfg.Pages.CallbackURL)
	}
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
