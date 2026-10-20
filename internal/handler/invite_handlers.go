package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/Sydekse/authpad/pkg/apierror"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type InviteHandlers struct {
	Invites *service.InviteService
	Email   apptypes.Mailer
	Auth    *service.AuthService
	IdP     *service.IdPService
	Cfg     *apptypes.AppConfig
}

func (h *InviteHandlers) Create(w http.ResponseWriter, r *http.Request) {
	actor, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP)
	if !ok {
		userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
		if !ok {
			return
		}
		actor = *userID
		if h.Cfg.Hooks.InvitePolicy == nil {
			apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
			return
		}
	}
	var body struct {
		Email       string         `json:"email"`
		Role        string         `json:"role"`
		Payload     map[string]any `json:"payload"`
		CallbackURL string         `json:"callback_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	inviteURL, ok := inviteCallbackURL(body.CallbackURL, h.Cfg)
	if !ok {
		apierror.BadRequest(w, "INVALID_CALLBACK_URL", "callback_url must be an http(s) URL on an allowed origin")
		return
	}
	token, inv, err := h.Invites.Issue(r.Context(), actor, body.Email, body.Role, body.Payload)
	if err != nil {
		apierror.Forbidden(w, "INVITE_DENIED", err.Error())
		return
	}
	if inviteURL == "" {
		inviteURL = strings.TrimRight(h.Cfg.Pages.SignUpURL, "/")
	}
	if inviteURL != "" {
		sep := "?"
		if strings.Contains(inviteURL, "?") {
			sep = "&"
		}
		inviteURL = inviteURL + sep + "token=" + url.QueryEscape(token)
		if h.Email != nil {
			if err := h.Email.SendInvitation(inv.Email, inviteURL, body.Role); err != nil {
				log.Warn().Err(err).Str("invitation_id", inv.ID.String()).Msg("invitation email not sent")
			}
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         inv.ID.String(),
		"email":      inv.Email,
		"role":       inv.Role,
		"expires_at": inv.ExpiresAt,
		"token":      token,
	})
}

func (h *InviteHandlers) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP); !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	list, err := h.Invites.List(r.Context())
	if err != nil {
		apierror.Internal(w, "LIST_FAILED", "Could not list invitations")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": list})
}

func (h *InviteHandlers) Revoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP); !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid invitation ID")
		return
	}
	if err := h.Invites.Revoke(r.Context(), id); err != nil {
		apierror.Internal(w, "REVOKE_FAILED", "Could not revoke invitation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *InviteHandlers) Validate(w http.ResponseWriter, r *http.Request) {
	inv, err := h.Invites.Validate(r.Context(), tokenParam(r))
	if err != nil {
		status := http.StatusBadRequest
		code := "INVITE_INVALID"
		if errors.Is(err, service.ErrInviteRevoked) {
			code = "INVITE_REVOKED"
		}
		if errors.Is(err, service.ErrInviteUsed) {
			code = "INVITE_USED"
		}
		apierror.WriteJSON(w, status, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email":      inv.Email,
		"role":       inv.Role,
		"expires_at": inv.ExpiresAt,
	})
}

func (h *InviteHandlers) Redeem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string         `json:"token"`
		Name     string         `json:"name"`
		Password string         `json:"password"`
		Profile  map[string]any `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	result, err := h.Invites.Redeem(r.Context(), body.Token, body.Name, body.Password, body.Profile, clientIP(r, h.Cfg), r.Header.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, service.ErrEmailTaken) {
			apierror.Conflict(w, "EMAIL_TAKEN", "An account with this email already exists")
			return
		}
		apierror.BadRequest(w, "REDEEM_FAILED", err.Error())
		return
	}
	if result.Token != "" {
		setSessionCookie(w, result.Token, h.Cfg)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":    UserInfo{ID: result.UserID.String(), Email: result.Email, Name: result.Name},
		"session": SessionInfo{ID: result.SessionID.String(), ExpiresAt: result.ExpiresAt},
		"token":   result.Token,
	})
}
