package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/auth-project/goauth/internal/service"
	"github.com/auth-project/goauth/pkg/apierror"
	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AdminHandlers struct {
	IdP   *service.IdPService
	Auth  *service.AuthService
	Audit *service.AuditService
	Cfg   *apptypes.AppConfig
}

func (h *AdminHandlers) AssignRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP); !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	userID, err := uuid.Parse(body.UserID)
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	role := strings.TrimSpace(strings.ToLower(body.Role))
	if !h.IdP.IsAllowedRole(role) {
		apierror.BadRequest(w, "INVALID_ROLE", "Role is not allowed")
		return
	}
	if err := h.IdP.AssignRoleByName(r.Context(), userID, role); err != nil {
		apierror.Internal(w, "ASSIGN_ROLE_FAILED", "Could not assign role")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandlers) RevokeRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP); !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	userID, err := uuid.Parse(body.UserID)
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	if err := h.IdP.RevokeRoleByName(r.Context(), userID, strings.ToLower(body.Role)); err != nil {
		apierror.Internal(w, "REVOKE_ROLE_FAILED", "Could not revoke role")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandlers) CreateGroup(w http.ResponseWriter, r *http.Request) {
	adminID, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP)
	if !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	var body struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		GroupType   string         `json:"group_type"`
		Metadata    map[string]any `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		apierror.BadRequest(w, "INVALID_NAME", "Group name is required")
		return
	}
	group, err := h.IdP.CreateGroup(r.Context(), body.Name, body.Description, body.GroupType, body.Metadata)
	if err != nil {
		apierror.Internal(w, "CREATE_GROUP_FAILED", "Could not create group")
		return
	}
	if h.Audit != nil {
		h.Audit.LogIdP(r.Context(), &adminID, "group.created", map[string]any{"group_id": group.ID.String()})
	}
	writeJSON(w, http.StatusCreated, group)
}

func (h *AdminHandlers) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	adminID, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP)
	if !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	groupID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid group ID")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	userID, err := uuid.Parse(body.UserID)
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	if err := h.IdP.AddGroupMember(r.Context(), groupID, userID, &adminID); err != nil {
		apierror.Internal(w, "ADD_MEMBER_FAILED", "Could not add group member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandlers) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP); !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	groupID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid group ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userId"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	if err := h.IdP.RemoveGroupMember(r.Context(), groupID, userID); err != nil {
		apierror.Internal(w, "REMOVE_MEMBER_FAILED", "Could not remove group member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandlers) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	if _, ok := isAdmin(r, h.Cfg, h.Auth, h.IdP); !ok {
		apierror.Forbidden(w, "FORBIDDEN", "Admin role required")
		return
	}
	logs, err := h.Audit.ListRecentAdmin(r.Context(), 200)
	if err != nil {
		apierror.Internal(w, "AUDIT_FAILED", "Could not load audit logs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}
