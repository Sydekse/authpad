package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/Sydekse/authpad/pkg/apierror"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type MFAHandlers struct {
	MFA  *service.MFAService
	Auth *service.AuthService
	Cfg  *apptypes.AppConfig
}

func (h *MFAHandlers) ListFactors(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	factors, err := h.MFA.ListFactors(r.Context(), *userID)
	if err != nil {
		apierror.Internal(w, "MFA_LIST_FAILED", "Could not list MFA factors")
		return
	}
	out := make([]map[string]any, 0, len(factors))
	for _, f := range factors {
		out = append(out, map[string]any{
			"id":          f.ID.String(),
			"factor_type": f.FactorType,
			"label":       f.Label,
			"verified":    f.Verified,
			"created_at":  f.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"factors": out})
}

func (h *MFAHandlers) EnrollTOTP(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Label == "" {
		body.Label = "Authenticator"
	}
	result, err := h.MFA.EnrollTOTP(r.Context(), *userID, body.Label)
	if err != nil {
		apierror.Internal(w, "MFA_ENROLL_FAILED", "Could not enroll TOTP")
		return
	}
	codes, _ := h.MFA.GenerateRecoveryCodes(r.Context(), *userID, 8)
	writeJSON(w, http.StatusOK, map[string]any{
		"factor_id":      result.FactorID,
		"secret":         result.Secret,
		"uri":            result.URI,
		"recovery_codes": codes,
	})
}

func (h *MFAHandlers) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		FactorID string `json:"factor_id"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	factorID, err := uuid.Parse(body.FactorID)
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid factor ID")
		return
	}
	if err := h.MFA.VerifyTOTP(r.Context(), *userID, factorID, body.Code); err != nil {
		apierror.BadRequest(w, "MFA_INVALID", "Invalid MFA code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *MFAHandlers) DeleteFactor(w http.ResponseWriter, r *http.Request) {
	userID, _, _, ok := requireSession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	factorID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest(w, "INVALID_ID", "Invalid factor ID")
		return
	}
	if err := h.MFA.DeleteFactor(r.Context(), *userID, factorID); err != nil {
		apierror.Internal(w, "MFA_DELETE_FAILED", "Could not delete factor")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *MFAHandlers) WebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	apierror.WriteJSON(w, http.StatusNotImplemented, "WEBAUTHN_DISABLED", "WebAuthn is not available until attestation verification is implemented")
}

func (h *MFAHandlers) WebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	apierror.WriteJSON(w, http.StatusNotImplemented, "WEBAUTHN_DISABLED", "WebAuthn is not available until attestation verification is implemented")
}

func (h *MFAHandlers) Challenge(w http.ResponseWriter, r *http.Request) {
	userID, sessID, token, ok := requirePendingMFASession(w, r, h.Auth, h.Cfg)
	if !ok {
		return
	}
	var body struct {
		FactorID string `json:"factor_id"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "INVALID_BODY", "Invalid JSON body")
		return
	}
	var factorID *uuid.UUID
	if strings.TrimSpace(body.FactorID) != "" {
		id, err := uuid.Parse(body.FactorID)
		if err != nil {
			apierror.BadRequest(w, "INVALID_ID", "Invalid factor ID")
			return
		}
		factorID = &id
	}
	if err := h.MFA.VerifyLoginCode(r.Context(), *userID, factorID, body.Code); err != nil {
		apierror.BadRequest(w, "MFA_INVALID", "Invalid MFA code")
		return
	}
	if err := h.Auth.SetSessionMFAPending(r.Context(), *sessID, false); err != nil {
		apierror.Internal(w, "MFA_FAILED", "Could not complete MFA challenge")
		return
	}
	if h.Cfg.Hooks.OnLogin != nil {
		if err := h.Cfg.Hooks.OnLogin(r.Context(), *userID); err != nil {
			_ = h.Auth.RevokeSession(r.Context(), *sessID)
			apierror.Internal(w, "LOGIN_HOOK_FAILED", "Login hook failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": token,
		"user":  map[string]string{"id": userID.String()},
	})
}
