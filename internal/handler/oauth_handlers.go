package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/auth-project/goauth/internal/service"
	"github.com/auth-project/goauth/pkg/apierror"
	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

type OAuthHandlers struct {
	OAuth *service.OAuthService
	Cfg   *apptypes.AppConfig
}

func (h *OAuthHandlers) OAuthInit(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider != "google" && provider != "github" {
		apierror.BadRequest(w, "INVALID_PROVIDER", "Unknown OAuth provider")
		return
	}
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	if redirectURI == "" {
		redirectURI = strings.TrimSpace(r.URL.Query().Get("callbackUrl"))
	}
	if redirectURI == "" {
		redirectURI = h.Cfg.Pages.CallbackURL
	}
	if redirectURI == "" {
		redirectURI = "/"
	}
	callbackBaseURL := getCallbackBaseURL(r)
	authURL, _, err := h.OAuth.AuthURL(provider, redirectURI, callbackBaseURL)
	if err != nil {
		log.Warn().Err(err).Str("provider", provider).Msg("oauth init")
		apierror.BadRequest(w, "OAUTH_CONFIG", "OAuth is not configured for this provider")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *OAuthHandlers) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider != "google" && provider != "github" {
		apierror.BadRequest(w, "INVALID_PROVIDER", "Unknown OAuth provider")
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		apierror.BadRequest(w, "MISSING_PARAMS", "Missing code or state")
		return
	}
	callbackBaseURL := getCallbackBaseURL(r)
	ip := parseIPFromRemote(r)
	ua := r.Header.Get("User-Agent")
	redirectURI, result, err := h.OAuth.Callback(r.Context(), provider, code, state, callbackBaseURL, ip, ua)
	if err != nil {
		log.Warn().Err(err).Str("provider", provider).Msg("oauth callback")
		if h.Cfg.Pages.ErrorURL != "" {
			http.Redirect(w, r, h.Cfg.Pages.ErrorURL+"?error=oauth_failed", http.StatusFound)
			return
		}
		apierror.BadRequest(w, "OAUTH_FAILED", "OAuth sign-in failed")
		return
	}
	setSessionCookie(w, result.Token, h.Cfg)
	finalRedirect := redirectURI
	if result.Token != "" {
		if u, err := url.Parse(strings.TrimSpace(redirectURI)); err == nil && u.Scheme != "" && u.Host != "" {
			q := u.Query()
			q.Set("token", result.Token)
			u.RawQuery = q.Encode()
			finalRedirect = u.String()
		} else if h.Cfg.Pages.CallbackURL != "" {
			u, _ := url.Parse(h.Cfg.Pages.CallbackURL)
			q := u.Query()
			q.Set("token", result.Token)
			u.RawQuery = q.Encode()
			finalRedirect = u.String()
		}
	}
	http.Redirect(w, r, finalRedirect, http.StatusFound)
}

func getCallbackBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}
