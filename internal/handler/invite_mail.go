package handler

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// tokenParam reads the {token} path segment percent-decoded. chi matches on
// the raw path, so a client that escapes the "=" padding of an opaque token as
// %3D would otherwise have the escape hashed into the lookup and never match.
func tokenParam(r *http.Request) string {
	raw := chi.URLParam(r, "token")
	if v, err := url.PathUnescape(raw); err == nil {
		return v
	}
	return raw
}

// sendOrgInvitation names the organization when the mailer supports it and
// logs, without the link, when the email could not be sent.
func sendOrgInvitation(r *http.Request, m apptypes.Mailer, orgs *service.OrgService, slug string, inviteID uuid.UUID, to, inviteURL, role string, expiresAt time.Time) {
	var err error
	om, ok := m.(apptypes.OrgInvitationMailer)
	name := ""
	if ok && orgs != nil {
		if org, gerr := orgs.GetBySlug(r.Context(), slug); gerr == nil && org != nil {
			name = org.Name
		}
	}
	if ok && name != "" {
		err = om.SendOrgInvitation(apptypes.OrgInvitationEmail{To: to, InviteURL: inviteURL, OrgName: name, Role: role, ExpiresAt: expiresAt})
	} else {
		err = m.SendInvitation(to, inviteURL, role)
	}
	if err != nil {
		log.Warn().Err(err).Str("invitation_id", inviteID.String()).Msg("organization invitation email not sent")
	}
}

// inviteCallbackURL checks the callback_url of an invite request. Its origin
// must be on the configured allowlist, so nobody can make authpad email an
// invite (and its token) that points at another site. Empty stays empty.
func inviteCallbackURL(raw string, cfg *apptypes.AppConfig) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", false
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, allowed := range inviteCallbackOrigins(cfg) {
		if origin == allowed {
			return strings.TrimRight(raw, "/"), true
		}
	}
	return "", false
}

func inviteCallbackOrigins(cfg *apptypes.AppConfig) []string {
	list := cfg.Invitations.CallbackOrigins
	if len(list) == 0 {
		list = append(append([]string{}, cfg.AllowedOrigins...), cfg.MagicLink.RedirectAllowlist...)
		for _, page := range []string{cfg.Pages.SignUpURL, cfg.Pages.SignInURL, cfg.Pages.CallbackURL, cfg.Pages.ResetPasswordURL, cfg.Pages.VerifyEmailURL} {
			if u, err := url.Parse(page); err == nil && u.Scheme != "" && u.Host != "" {
				list = append(list, u.Scheme+"://"+u.Host)
			}
		}
	}
	out := make([]string, 0, len(list))
	for _, o := range list {
		if o = strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/")); o != "" {
			out = append(out, o)
		}
	}
	return out
}
