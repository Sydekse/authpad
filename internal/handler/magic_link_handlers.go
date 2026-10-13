package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/middleware"
	"github.com/Sydekse/authpad/internal/security"
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
	// PKCE (RFC 7636), required when the code flow is on. Only S256 is supported.
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

const magicNonceCookie = "authpad_ml_nonce"

// Request always answers 202 with the same body once the JSON parses. All
// lookups, rate limiting and mail delivery happen after the response is decided.
// The one exception is a missing or malformed PKCE challenge while the code flow
// is on: that is a client error independent of the email or tenant, so it is a
// 400 and leaks nothing.
func (h *MagicLinkHandlers) Request(w http.ResponseWriter, r *http.Request) {
	var req magicLinkRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	if h.Links.CodeFlowActive() {
		if !service.ValidCodeChallenge(req.CodeChallenge) || (req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256") {
			apierror.BadRequest(w, "INVALID_CODE_CHALLENGE", "code_challenge (S256, base64url SHA-256 of the code_verifier) is required")
			return
		}
	}
	h.Links.Submit(service.MagicLinkRequest{
		Email:         req.Email,
		Tenant:        req.Tenant,
		RedirectTo:    req.RedirectTo,
		IP:            clientIP(r, h.Cfg),
		CodeChallenge: req.CodeChallenge,
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

func (h *MagicLinkHandlers) verifyPath() string {
	base := strings.TrimSuffix(h.Cfg.APIBasePath, "/")
	if base == "" {
		base = "/api/v1"
	}
	return base + "/magic-link/verify"
}

func setPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	// No form-action: browsers apply it to the redirect after the POST, which
	// goes to the app.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
}

var verifyPageTmpl = template.Must(template.New("verify").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
<title>Sign in</title>
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0}main{max-width:22rem;padding:1.5rem;text-align:center}button{font:inherit;padding:.6rem 1.4rem;cursor:pointer}</style>
</head><body><main>
<h1>Sign in to {{.App}}</h1>
<p>Press the button to finish signing in.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="tenant" value="{{.Tenant}}">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<button type="submit">Continue</button>
</form>
</main></body></html>
`))

// VerifyPage answers GET /magic-link/verify. It never consumes the token, so mail
// scanners and link prefetchers that follow the link cannot burn it or obtain a
// session. It renders a page whose button POSTs to Verify. The page loads no
// external resource, so the token in the URL cannot reach a third party, and it
// binds the POST to this browser with a SameSite=Strict nonce cookie.
func (h *MagicLinkHandlers) VerifyPage(w http.ResponseWriter, r *http.Request) {
	setPageHeaders(w)
	q := r.URL.Query()
	token := strings.TrimSpace(q.Get("token"))
	if token == "" || len(token) > 256 {
		h.fail(w, r)
		return
	}
	nonce, err := security.GenerateOpaqueToken()
	if err != nil {
		apierror.Internal(w, "LOGIN_FAILED", "Could not render sign-in page")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     magicNonceCookie,
		Value:    nonce,
		Path:     h.verifyPath(),
		MaxAge:   15 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.Cfg.Session.CookieSecure,
	})
	app := strings.TrimSpace(h.Cfg.Pages.AppName)
	if app == "" {
		app = "your account"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = verifyPageTmpl.Execute(w, map[string]string{
		"App": app, "Action": h.verifyPath(), "Token": token, "Tenant": q.Get("tenant"), "Nonce": nonce,
	})
}

// Verify answers POST /magic-link/verify (the interstitial's form) and is the
// only place the token is consumed. The form's nonce must equal the cookie set
// when the page was served, so a cross-site form post cannot sign a victim in
// with an attacker's token.
func (h *MagicLinkHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	setPageHeaders(w)

	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r)
		return
	}
	cookie, _ := r.Cookie(magicNonceCookie)
	nonce := r.PostForm.Get("nonce")
	if cookie == nil || cookie.Value == "" || nonce == "" || !security.EqualSecret(cookie.Value, nonce) {
		h.fail(w, r)
		return
	}
	// The nonce is single use.
	http.SetCookie(w, &http.Cookie{Name: magicNonceCookie, Path: h.verifyPath(), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: h.Cfg.Session.CookieSecure})

	ip := clientIP(r, h.Cfg)
	ua := r.Header.Get("User-Agent")
	res, err := h.Links.Verify(r.Context(), r.PostForm.Get("token"), r.PostForm.Get("tenant"), ip, ua)
	if err != nil {
		h.fail(w, r)
		return
	}
	user := res.User

	if h.Links.CodeFlowActive() && h.destination(res) == "" {
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
	if !h.Links.CodeFlowActive() {
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
	if h.Links.CodeFlowActive() {
		dest := h.destination(res)
		code, err := h.Links.CreateCode(r.Context(), sessionID, res.Organization.ID, dest, res.CodeChallenge)
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
	CodeVerifier   string `json:"code_verifier"`
}

// Exchange redeems a one-time code for the session token. Server-to-server only.
func (h *MagicLinkHandlers) Exchange(w http.ResponseWriter, r *http.Request) {
	secret := h.Cfg.MagicLink.ExchangeSecret
	if secret == "" || !h.Links.CodeFlowActive() {
		apierror.NotFound(w, "NOT_FOUND", "Not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !h.Links.AllowExchange(r.Context(), clientIP(r, h.Cfg)) {
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
	ex, err := h.Links.Exchange(r.Context(), body.Code, body.RedirectOrigin, body.CodeVerifier)
	if err != nil {
		apierror.BadRequest(w, "INVALID_CODE", "This code is invalid or has expired")
		return
	}
	if h.Audit != nil {
		h.Audit.LogAuth(r.Context(), &ex.User.ID, "magic_link.exchange", clientIP(r, h.Cfg), r.Header.Get("User-Agent"), map[string]any{
			"is_member": ex.IsMember,
		})
	}
	// org_id and role are null unless the user is an active member of the tenant.
	var orgID, role any
	if ex.OrgID != nil {
		orgID = ex.OrgID.String()
	}
	if ex.Role != "" {
		role = ex.Role
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_token": ex.SessionToken,
		"expires_at":    ex.ExpiresAt.UTC().Format(time.RFC3339),
		"user":          map[string]string{"id": ex.User.ID.String(), "email": ex.User.Email},
		"org_id":        orgID,
		"is_member":     ex.IsMember,
		"role":          role,
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
