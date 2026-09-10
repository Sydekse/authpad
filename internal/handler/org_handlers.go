package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/Sydekse/authpad/pkg/apierror"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type OrgHandlers struct {
	Orgs  *service.OrgService
	Auth  *service.AuthService
	Email apptypes.Mailer
	Cfg   *apptypes.AppConfig
}

func writeOrgErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrTenancyDisabled):
		apierror.NotFound(w, "TENANCY_DISABLED", err.Error())
	case errors.Is(err, service.ErrOrgNotFound):
		apierror.NotFound(w, "ORG_NOT_FOUND", err.Error())
	case errors.Is(err, service.ErrNotOrgMember), errors.Is(err, service.ErrOrgForbidden):
		apierror.Forbidden(w, "FORBIDDEN", err.Error())
	case errors.Is(err, service.ErrMembershipLimit), errors.Is(err, service.ErrOrgCreateDisabled), errors.Is(err, service.ErrInvalidSlug):
		apierror.BadRequest(w, "ORG_INVALID", err.Error())
	default:
		apierror.Internal(w, "ORG_FAILED", err.Error())
	}
}

func (h *OrgHandlers) Create(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		Name     string         `json:"name"`
		Slug     string         `json:"slug"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	org, err := h.Orgs.Create(r.Context(), *userID, body.Name, body.Slug, body.Metadata)
	if err != nil {
		writeOrgErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

func (h *OrgHandlers) List(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	list, err := h.Orgs.ListForUser(r.Context(), *userID)
	if err != nil {
		writeOrgErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": list})
}

func (h *OrgHandlers) Get(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	org, err := h.Orgs.GetBySlug(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		writeOrgErr(w, err)
		return
	}
	if _, err := h.Orgs.RequireMember(r.Context(), org.ID, *userID); err != nil {
		writeOrgErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (h *OrgHandlers) Patch(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		Name     string         `json:"name"`
		ImageURL string         `json:"image_url"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	if err := h.Orgs.Update(r.Context(), chi.URLParam(r, "slug"), *userID, body.Name, body.ImageURL, body.Metadata); err != nil {
		writeOrgErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *OrgHandlers) Members(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	members, err := h.Orgs.ListMembers(r.Context(), chi.URLParam(r, "slug"), *userID)
	if err != nil {
		writeOrgErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (h *OrgHandlers) Invite(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		Email       string `json:"email"`
		Role        string `json:"role"`
		CallbackURL string `json:"callback_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	token, inv, err := h.Orgs.Invite(r.Context(), chi.URLParam(r, "slug"), *userID, body.Email, body.Role)
	if err != nil {
		writeOrgErr(w, err)
		return
	}
	inviteURL := strings.TrimRight(body.CallbackURL, "/")
	if inviteURL != "" {
		sep := "?"
		if strings.Contains(inviteURL, "?") {
			sep = "&"
		}
		inviteURL = inviteURL + sep + "token=" + token
		if h.Email != nil {
			_ = h.Email.SendInvitation(body.Email, inviteURL, body.Role)
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

func (h *OrgHandlers) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid invitation ID")
		return
	}
	if err := h.Orgs.RevokeInvite(r.Context(), chi.URLParam(r, "slug"), *userID, id); err != nil {
		writeOrgErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *OrgHandlers) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	org, err := h.Orgs.AcceptInvite(r.Context(), body.Token, *userID)
	if err != nil {
		writeOrgErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (h *OrgHandlers) Switch(w http.ResponseWriter, r *http.Request) {
	userID, sessID, _, ok := requireFullSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		OrganizationID string `json:"organization_id"`
		Slug           string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	var orgID uuid.UUID
	if strings.TrimSpace(body.OrganizationID) != "" {
		id, err := uuid.Parse(body.OrganizationID)
		if err != nil {
			apierror.BadRequest(w, "INVALID_ID", "Invalid organization ID")
			return
		}
		orgID = id
	} else if strings.TrimSpace(body.Slug) != "" {
		org, err := h.Orgs.GetBySlug(r.Context(), body.Slug)
		if err != nil {
			writeOrgErr(w, err)
			return
		}
		orgID = org.ID
	} else {
		if err := h.Orgs.ClearActive(r.Context(), *sessID); err != nil {
			writeOrgErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := h.Orgs.SwitchActive(r.Context(), *sessID, *userID, orgID); err != nil {
		writeOrgErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
