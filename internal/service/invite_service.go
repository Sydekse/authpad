package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/idp"
	idp_repo "github.com/Sydekse/authpad/internal/repository/idp"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
)

var (
	ErrInviteInvalid = errors.New("invitation is invalid or expired")
	ErrInviteRevoked = errors.New("invitation has been revoked")
	ErrInviteUsed    = errors.New("invitation has already been used")
)

type InviteService struct {
	repo    *idp_repo.InvitationRepo
	account *AccountService
	idp     *IdPService
	cfg     *apptypes.AppConfig
}

func NewInviteService(repo *idp_repo.InvitationRepo, account *AccountService, idp *IdPService, cfg *apptypes.AppConfig) *InviteService {
	return &InviteService{repo: repo, account: account, idp: idp, cfg: cfg}
}

func (s *InviteService) Issue(ctx context.Context, actor uuid.UUID, email, role string, payload map[string]any) (rawToken string, inv *idp.Invitation, err error) {
	email = strings.ToLower(strings.TrimSpace(email))
	role = strings.TrimSpace(strings.ToLower(role))
	if email == "" {
		return "", nil, errors.New("email is required")
	}
	if s.cfg.Hooks.InvitePolicy != nil {
		if err := s.cfg.Hooks.InvitePolicy(ctx, actor, email, role); err != nil {
			return "", nil, err
		}
	}
	rawToken, err = security.GenerateOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	ttl := s.cfg.Invitations.TTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	body, _ := json.Marshal(payload)
	if len(body) == 0 {
		body = []byte("{}")
	}
	inv = &idp.Invitation{
		ID:        uuid.New(),
		Email:     email,
		Role:      role,
		Payload:   body,
		TokenHash: security.HashToken(rawToken),
		ExpiresAt: time.Now().Add(ttl),
		InvitedBy: &actor,
		CreatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, inv); err != nil {
		return "", nil, err
	}
	return rawToken, inv, nil
}

func (s *InviteService) Validate(ctx context.Context, rawToken string) (*idp.Invitation, error) {
	inv, err := s.repo.GetByTokenHash(ctx, security.HashToken(strings.TrimSpace(rawToken)))
	if err != nil || inv == nil {
		return nil, ErrInviteInvalid
	}
	if inv.RevokedAt != nil {
		return nil, ErrInviteRevoked
	}
	if inv.RedeemedAt != nil {
		return nil, ErrInviteUsed
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, ErrInviteInvalid
	}
	return inv, nil
}

func (s *InviteService) List(ctx context.Context) ([]idp.Invitation, error) {
	return s.repo.List(ctx, 200)
}

func (s *InviteService) Revoke(ctx context.Context, id uuid.UUID) error {
	return s.repo.Revoke(ctx, id)
}

func (s *InviteService) Redeem(ctx context.Context, rawToken, name, password string, extraProfile map[string]any, ip, ua string) (*CreateAccountResult, error) {
	inv, err := s.Validate(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	profile := map[string]any{"name": name}
	if len(inv.Payload) > 0 {
		var payload map[string]any
		_ = json.Unmarshal(inv.Payload, &payload)
		for k, v := range payload {
			profile[k] = v
		}
	}
	for k, v := range extraProfile {
		profile[k] = v
	}
	result, err := s.account.CreateAccount(ctx, CreateAccountRequest{
		Email:         inv.Email,
		Password:      password,
		Profile:       profile,
		EmailVerified: true,
	}, ip, ua)
	if err != nil {
		return nil, err
	}
	if inv.Role != "" && s.idp != nil {
		if err := s.idp.AssignRoleByName(ctx, result.UserID, inv.Role); err != nil {
			s.account.authSvc.RollbackUser(ctx, result.UserID)
			if s.idp != nil {
				_ = s.idp.RollbackProfile(ctx, result.UserID)
			}
			return nil, err
		}
	}
	// Auth and IdP live on separate databases, so redeem cannot be one SQL
	// transaction. MarkRedeemed last; roll back the new account on failure.
	if err := s.repo.MarkRedeemed(ctx, inv.ID, result.UserID); err != nil {
		s.account.authSvc.RollbackUser(ctx, result.UserID)
		if s.idp != nil {
			_ = s.idp.RollbackProfile(ctx, result.UserID)
		}
		return nil, err
	}
	return result, nil
}
