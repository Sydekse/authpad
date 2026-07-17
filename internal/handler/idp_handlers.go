package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/auth-project/authpad/internal/domain/idp"
	"github.com/auth-project/authpad/internal/service"
	"github.com/auth-project/authpad/pkg/apierror"
	"github.com/auth-project/authpad/internal/apptypes"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type IdPHandlers struct {
	Auth    *service.AuthService
	IdP     *service.IdPService
	Account *service.AccountService
	Audit   *service.AuditService
	Cfg     *apptypes.AppConfig
}

type UserInfoResponse struct {
	Valid   bool         `json:"valid"`
	User    *UserInfo    `json:"user,omitempty"`
	Roles   []string     `json:"roles,omitempty"`
	Groups  []idp.Group  `json:"groups,omitempty"`
	Session *SessionInfo `json:"session,omitempty"`
}

type AccountResponse struct {
	UserID   string         `json:"user_id"`
	Email    string         `json:"email"`
	Name     string         `json:"name"`
	ImageURL string         `json:"image_url,omitempty"`
	Bio      string         `json:"bio,omitempty"`
	Roles    []string       `json:"roles"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (h *IdPHandlers) Userinfo(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	h.writeUserInfo(w, r, *userID)
}

func (h *IdPHandlers) writeUserInfo(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	profile, err := h.IdP.GetProfile(r.Context(), userID)
	if err != nil || profile == nil {
		apierror.NotFound(w, "PROFILE_NOT_FOUND", "Profile not found")
		return
	}
	roles, _ := h.IdP.GetRoleNames(r.Context(), userID)
	groups, _ := h.IdP.GetGroups(r.Context(), userID)
	authUser, _ := h.Auth.GetUserByID(r.Context(), userID)
	email, verified := "", false
	if authUser != nil {
		email = authUser.Email
		verified = authUser.EmailVerified
	}
	token := getSessionToken(r, h.Cfg)
	sess, _ := h.Auth.GetSessionByToken(r.Context(), token)
	var sessionInfo *SessionInfo
	if sess != nil {
		sessionInfo = &SessionInfo{ID: sess.ID.String(), ExpiresAt: sess.ExpiresAt.Format(time.RFC3339)}
	}
	writeJSON(w, http.StatusOK, UserInfoResponse{
		Valid: true,
		User:  &UserInfo{ID: userID.String(), Email: email, Name: profile.Name, EmailVerified: verified},
		Roles: roles, Groups: groups, Session: sessionInfo,
	})
}

func (h *IdPHandlers) GetUserByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	if !canAccessUser(r, h.Cfg, h.Auth, h.IdP, id) {
		apierror.Forbidden(w, "FORBIDDEN", "Not allowed to access this user")
		return
	}
	profile, err := h.IdP.GetProfile(r.Context(), id)
	if err != nil || profile == nil {
		apierror.NotFound(w, "NOT_FOUND", "User not found")
		return
	}
	roles, _ := h.IdP.GetRoleNames(r.Context(), id)
	groups, _ := h.IdP.GetGroups(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": id.String(), "name": profile.Name, "image_url": profile.ImageURL, "roles": roles, "groups": groups,
	})
}

func (h *IdPHandlers) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	if !canAccessUser(r, h.Cfg, h.Auth, h.IdP, id) {
		apierror.Forbidden(w, "FORBIDDEN", "Not allowed")
		return
	}
	roles, err := h.IdP.GetRoleNames(r.Context(), id)
	if err != nil {
		apierror.Internal(w, "ROLES_FAILED", "Could not load roles")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (h *IdPHandlers) GetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid user ID")
		return
	}
	if !canAccessUser(r, h.Cfg, h.Auth, h.IdP, id) {
		apierror.Forbidden(w, "FORBIDDEN", "Not allowed")
		return
	}
	groups, err := h.IdP.GetGroups(r.Context(), id)
	if err != nil {
		apierror.Internal(w, "GROUPS_FAILED", "Could not load groups")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
}

func (h *IdPHandlers) GetAccount(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	profile, err := h.IdP.GetProfile(r.Context(), *userID)
	if err != nil || profile == nil {
		apierror.NotFound(w, "PROFILE_NOT_FOUND", "Profile not found")
		return
	}
	authUser, _ := h.Auth.GetUserByID(r.Context(), *userID)
	email := ""
	if authUser != nil {
		email = authUser.Email
	}
	roles, _ := h.IdP.GetRoleNames(r.Context(), *userID)
	var metadata map[string]any
	_ = json.Unmarshal(profile.Metadata, &metadata)
	writeJSON(w, http.StatusOK, AccountResponse{
		UserID: userID.String(), Email: email, Name: profile.Name, ImageURL: profile.ImageURL, Bio: profile.Bio, Roles: roles, Metadata: metadata,
	})
}

func (h *IdPHandlers) GetAccountComplete(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	roles, _ := h.IdP.GetRoleNames(r.Context(), *userID)
	writeJSON(w, http.StatusOK, map[string]bool{"complete": len(roles) > 0})
}

func (h *IdPHandlers) PatchAccount(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	existing, _ := h.IdP.GetProfile(r.Context(), *userID)
	if existing == nil {
		apierror.NotFound(w, "PROFILE_NOT_FOUND", "Profile not found")
		return
	}
	merged := map[string]any{"name": existing.Name}
	if existing.ImageURL != "" {
		merged["image_url"] = existing.ImageURL
	}
	if existing.Bio != "" {
		merged["bio"] = existing.Bio
	}
	var existingMeta map[string]any
	_ = json.Unmarshal(existing.Metadata, &existingMeta)
	for k, v := range existingMeta {
		merged[k] = v
	}
	for k, v := range body {
		if k == "metadata" {
			if meta, ok := v.(map[string]any); ok {
				for mk, mv := range meta {
					merged[mk] = mv
				}
			}
			continue
		}
		merged[k] = v
	}
	profile, err := h.Account.ValidateProfileUpdate(merged)
	if err != nil {
		apierror.BadRequest(w, "INVALID_PROFILE", err.Error())
		return
	}
	if err := h.IdP.UpdateProfile(r.Context(), *userID, profile); err != nil {
		apierror.Internal(w, "UPDATE_FAILED", "Could not update profile")
		return
	}
	if h.Audit != nil {
		h.Audit.LogIdP(r.Context(), userID, "profile.updated", nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdPHandlers) AssignRole(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	role := strings.TrimSpace(strings.ToLower(body.Role))
	if !h.IdP.IsAllowedRole(role) {
		apierror.BadRequest(w, "INVALID_ROLE", "Role is not allowed")
		return
	}
	if err := h.IdP.AssignRoleByName(r.Context(), *userID, role); err != nil {
		apierror.Internal(w, "ASSIGN_ROLE_FAILED", "Could not assign role")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdPHandlers) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	sessions, err := h.Auth.ListSessions(r.Context(), *userID)
	if err != nil {
		apierror.Internal(w, "SESSIONS_FAILED", "Could not list sessions")
		return
	}
	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, map[string]any{
			"id": s.ID.String(), "ip_address": s.IPAddress, "user_agent": s.UserAgent,
			"created_at": s.CreatedAt, "expires_at": s.ExpiresAt, "last_active_at": s.LastActiveAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (h *IdPHandlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid session ID")
		return
	}
	sessions, _ := h.Auth.ListSessions(r.Context(), *userID)
	found := false
	for _, s := range sessions {
		if s.ID == sessionID {
			found = true
			break
		}
	}
	if !found {
		apierror.NotFound(w, "NOT_FOUND", "Session not found")
		return
	}
	_ = h.Auth.RevokeSession(r.Context(), sessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *IdPHandlers) GetAccountAudit(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	logs, err := h.Audit.ListForUser(r.Context(), *userID, 200)
	if err != nil {
		apierror.Internal(w, "AUDIT_FAILED", "Could not load audit logs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

func (h *IdPHandlers) ExportAccount(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	data, err := h.Account.ExportJSON(r.Context(), *userID)
	if err != nil {
		apierror.Internal(w, "EXPORT_FAILED", "Could not export account data")
		return
	}
	if h.Audit != nil {
		h.Audit.LogAuth(r.Context(), userID, "account.export", parseIPFromRemote(r), r.Header.Get("User-Agent"), nil)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=account-export.json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *IdPHandlers) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	ip := parseIPFromRemote(r)
	ua := r.Header.Get("User-Agent")
	if err := h.Account.DeleteAccount(r.Context(), *userID, ip, ua); err != nil {
		apierror.Internal(w, "DELETE_FAILED", "Could not delete account")
		return
	}
	if h.Cfg.Hooks.OnDelete != nil {
		_ = h.Cfg.Hooks.OnDelete(r.Context(), *userID)
	}
	clearSessionCookie(w, h.Cfg)
	w.WriteHeader(http.StatusNoContent)
}
