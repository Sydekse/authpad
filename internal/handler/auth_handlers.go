package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/auth-project/authpad/internal/apptypes"
	"github.com/auth-project/authpad/internal/service"
	"github.com/auth-project/authpad/pkg/apierror"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type AuthHandlers struct {
	Account *service.AccountService
	Auth    *service.AuthService
	IdP     *service.IdPService
	Email   *service.EmailService
	Audit   *service.AuditService
	Cfg     *apptypes.AppConfig
}

type signupRequest struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	Name     string         `json:"name"`
	Profile  map[string]any `json:"profile"`
}

type loginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

type passwordResetRequestBody struct {
	Email string `json:"email"`
}

type passwordResetBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *AuthHandlers) Signup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	profile := req.Profile
	if profile == nil {
		profile = map[string]any{}
	}
	if req.Name != "" {
		profile["name"] = req.Name
	}

	ip := parseIPFromRemote(r)
	ua := r.Header.Get("User-Agent")

	result, err := h.Account.CreateAccount(r.Context(), service.CreateAccountRequest{
		Email:    strings.TrimSpace(req.Email),
		Password: req.Password,
		Profile:  profile,
	}, ip, ua)
	if err != nil {
		if err == service.ErrEmailTaken {
			apierror.Conflict(w, "EMAIL_TAKEN", "An account with this email already exists")
			return
		}
		if err == service.ErrWeakPassword {
			apierror.BadRequest(w, "WEAK_PASSWORD", err.Error())
			return
		}
		apierror.BadRequest(w, "SIGNUP_FAILED", err.Error())
		return
	}

	if h.Cfg.Email.RequireVerification {
		if token, err := h.Auth.CreateEmailVerificationToken(r.Context(), result.UserID); err == nil && h.Email != nil {
			_ = h.Email.SendEmailVerification(result.Email, h.Email.BuildVerifyURL(token))
		}
		// Do not log the user in until email is verified.
		if result.SessionID != uuid.Nil {
			_ = h.Auth.RevokeSession(r.Context(), result.SessionID)
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":                    true,
			"email":                 result.Email,
			"requires_verification": true,
		})
		return
	}

	setSessionCookie(w, result.Token, h.Cfg)
	writeJSON(w, http.StatusCreated, SessionResponse{
		User: UserInfo{ID: result.UserID.String(), Email: result.Email, Name: result.Name},
		Session: SessionInfo{ID: result.SessionID.String(), ExpiresAt: result.ExpiresAt},
		Token: result.Token,
	})
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}

	user, err := h.Auth.ValidatePassword(r.Context(), strings.TrimSpace(req.Email), req.Password)
	if err != nil {
		if err == service.ErrEmailNotVerified {
			apierror.Forbidden(w, "EMAIL_NOT_VERIFIED", "Email verification required")
			return
		}
		apierror.Unauthorized(w, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	ip := parseIPFromRemote(r)
	ua := r.Header.Get("User-Agent")
	ttl := h.Cfg.Session.TTL
	if req.RememberMe {
		ttl = h.Cfg.Session.RememberMeTTL
		if ttl <= 0 {
			ttl = 30 * 24 * time.Hour
		}
	}
	token, sess, err := h.Auth.CreateSessionWithTTL(r.Context(), user.ID, ip, ua, ttl)
	if err != nil {
		apierror.Internal(w, "LOGIN_FAILED", "Could not create session")
		return
	}

	if h.Audit != nil {
		h.Audit.LogAuth(r.Context(), &user.ID, "login.success", ip, ua, map[string]any{"remember_me": req.RememberMe})
	}
	if h.Cfg.Hooks.OnLogin != nil {
		_ = h.Cfg.Hooks.OnLogin(r.Context(), user.ID)
	}

	setSessionCookie(w, token, h.Cfg, ttl)
	name := user.Email
	if h.IdP != nil {
		if profile, _ := h.IdP.GetProfile(r.Context(), user.ID); profile != nil {
			name = profile.Name
		}
	}
	writeJSON(w, http.StatusOK, SessionResponse{
		User: UserInfo{ID: user.ID.String(), Email: user.Email, Name: name, EmailVerified: user.EmailVerified},
		Session: SessionInfo{ID: sess.ID.String(), ExpiresAt: sess.ExpiresAt.Format(time.RFC3339)},
		Token: token,
	})
}

func (h *AuthHandlers) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		apierror.BadRequest(w, "INVALID_EMAIL", "Email is required")
		return
	}
	token, err := h.Auth.CreatePasswordResetToken(r.Context(), email)
	if err != nil {
		apierror.Internal(w, "RESET_REQUEST_FAILED", "Could not process request")
		return
	}
	if token != "" && h.Email != nil {
		resetURL := h.Email.BuildResetURL(token)
		if err := h.Email.SendPasswordReset(email, resetURL); err != nil {
			log.Error().Err(err).Msg("password reset email failed")
		}
		if h.Cfg.Env != "production" {
			log.Info().Str("reset_link", resetURL).Msg("password reset token created")
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *AuthHandlers) PasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		apierror.BadRequest(w, "INVALID_TOKEN", "Token is required")
		return
	}
	if err := h.Auth.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		if err == service.ErrResetTokenInvalid || err == service.ErrNoPasswordCredential {
			apierror.BadRequest(w, "INVALID_OR_EXPIRED_TOKEN", "This reset link is invalid or has expired")
			return
		}
		if err == service.ErrWeakPassword {
			apierror.BadRequest(w, "WEAK_PASSWORD", err.Error())
			return
		}
		apierror.Internal(w, "RESET_FAILED", "Could not reset password")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		apierror.BadRequest(w, "INVALID_TOKEN", "Token is required")
		return
	}
	if err := h.Auth.VerifyEmail(r.Context(), token); err != nil {
		apierror.BadRequest(w, "INVALID_OR_EXPIRED_TOKEN", "Verification link is invalid or expired")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *AuthHandlers) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid request body")
		return
	}
	emailAddr := strings.TrimSpace(body.Email)
	if emailAddr == "" {
		apierror.BadRequest(w, "INVALID_EMAIL", "Email is required")
		return
	}
	// Always return ok to avoid account enumeration.
	defer writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	user, err := h.Auth.GetUserByEmail(r.Context(), emailAddr)
	if err != nil || user == nil || user.EmailVerified {
		return
	}
	token, err := h.Auth.CreateEmailVerificationToken(r.Context(), user.ID)
	if err != nil || h.Email == nil {
		return
	}
	_ = h.Email.SendEmailVerification(user.Email, h.Email.BuildVerifyURL(token))
}

func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	token := getSessionToken(r, h.Cfg)
	if token != "" {
		if sess, _ := h.Auth.GetSessionByToken(r.Context(), token); sess != nil {
			_ = h.Auth.RevokeSession(r.Context(), sess.ID)
			if h.Audit != nil {
				h.Audit.LogAuth(r.Context(), &sess.UserID, "logout", parseIPFromRemote(r), r.Header.Get("User-Agent"), nil)
			}
		}
	}
	clearSessionCookie(w, h.Cfg)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandlers) LogoutAll(w http.ResponseWriter, r *http.Request) {
	token := getSessionToken(r, h.Cfg)
	if token != "" {
		if sess, _ := h.Auth.GetSessionByToken(r.Context(), token); sess != nil {
			_, _ = h.Auth.RevokeAllSessionsForUser(r.Context(), sess.UserID)
			if h.Audit != nil {
				h.Audit.LogAuth(r.Context(), &sess.UserID, "logout.all", parseIPFromRemote(r), r.Header.Get("User-Agent"), nil)
			}
		}
	}
	clearSessionCookie(w, h.Cfg)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandlers) Session(w http.ResponseWriter, r *http.Request) {
	token := getSessionToken(r, h.Cfg)
	if token == "" {
		apierror.UnauthorizedWithRedirect(w, h.Cfg.Pages.SignInURL, r.URL.RequestURI(), "NO_SESSION", "No session token")
		return
	}
	sess, err := h.Auth.GetSessionByToken(r.Context(), token)
	if err != nil || sess == nil {
		apierror.UnauthorizedWithRedirect(w, h.Cfg.Pages.SignInURL, r.URL.RequestURI(), "INVALID_SESSION", "Session expired or invalid")
		return
	}
	if newToken, _, err := h.Auth.RotateSession(r.Context(), sess); err == nil && newToken != "" {
		setSessionCookie(w, newToken, h.Cfg)
		token = newToken
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true,
		"user":  map[string]string{"id": sess.UserID.String()},
		"token": token,
		"session": map[string]any{
			"id":         sess.ID.String(),
			"created_at": sess.CreatedAt.Format(time.RFC3339),
			"expires_at": sess.ExpiresAt.Format(time.RFC3339),
		},
	})
}
