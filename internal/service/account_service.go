package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	auth_repo "github.com/auth-project/authpad/internal/repository/auth"
	"github.com/auth-project/authpad/internal/apptypes"
	"github.com/google/uuid"
)

var ErrEmailTaken = errors.New("email already taken")

type CreateAccountRequest struct {
	Email    string
	Password string
	Profile  map[string]any
}

type CreateAccountResult struct {
	UserID    uuid.UUID
	Email     string
	Name      string
	Token     string
	SessionID uuid.UUID
	ExpiresAt string
}

type AccountService struct {
	authSvc   *AuthService
	idpSvc    *IdPService
	userRepo  *auth_repo.UserAuthRepo
	credRepo  *auth_repo.CredentialRepo
	auditSvc  *AuditService
	schema    apptypes.ProfileSchema
	hooks     apptypes.Hooks
}

func NewAccountService(
	authSvc *AuthService,
	idpSvc *IdPService,
	userRepo *auth_repo.UserAuthRepo,
	credRepo *auth_repo.CredentialRepo,
	auditSvc *AuditService,
	schema apptypes.ProfileSchema,
	hooks apptypes.Hooks,
) *AccountService {
	return &AccountService{
		authSvc:  authSvc,
		idpSvc:   idpSvc,
		userRepo: userRepo,
		credRepo: credRepo,
		auditSvc: auditSvc,
		schema:   schema,
		hooks:    hooks,
	}
}

func (s *AccountService) CreateAccount(ctx context.Context, req CreateAccountRequest, ipAddress, userAgent string) (*CreateAccountResult, error) {
	if req.Email == "" || req.Password == "" {
		return nil, ErrInvalidCredentials
	}
	profile, err := s.schema.ValidateProfile(req.Profile)
	if err != nil {
		return nil, err
	}

	existing, _ := s.userRepo.GetByEmail(ctx, req.Email)
	if existing != nil {
		return nil, ErrEmailTaken
	}

	userID := uuid.New()
	if err := s.authSvc.CreateUserAuth(ctx, userID, req.Email); err != nil {
		return nil, err
	}

	if err := s.authSvc.CreateCredential(ctx, userID, req.Password); err != nil {
		s.authSvc.RollbackUser(ctx, userID)
		return nil, err
	}

	if s.idpSvc != nil {
		if err := s.idpSvc.CreateProfile(ctx, userID, profile); err != nil {
			s.authSvc.RollbackUser(ctx, userID)
			return nil, err
		}
	}

	token, sess, err := s.authSvc.CreateSession(ctx, userID, ipAddress, userAgent)
	if err != nil {
		if s.idpSvc != nil {
			_ = s.idpSvc.RollbackProfile(ctx, userID)
		}
		s.authSvc.RollbackUser(ctx, userID)
		return nil, err
	}

	if s.auditSvc != nil {
		s.auditSvc.LogAuth(ctx, &userID, "account.created", ipAddress, userAgent, map[string]any{"email": req.Email})
	}
	if s.hooks.OnSignup != nil {
		_ = s.hooks.OnSignup(ctx, userID, req.Email)
	}

	return &CreateAccountResult{
		UserID:    userID,
		Email:     req.Email,
		Name:      profile.Name,
		Token:     token,
		SessionID: sess.ID,
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *AccountService) DeleteAccount(ctx context.Context, userID uuid.UUID, ip, ua string) error {
	if s.auditSvc != nil {
		s.auditSvc.LogAuth(ctx, &userID, "account.deleted", ip, ua, nil)
	}
	if err := s.authSvc.DeleteUserAuth(ctx, userID); err != nil {
		return err
	}
	if s.idpSvc != nil {
		return s.idpSvc.DeleteProfile(ctx, userID)
	}
	return nil
}

func (s *AccountService) ExportAccount(ctx context.Context, userID uuid.UUID) (map[string]any, error) {
	out := map[string]any{"user_id": userID.String()}
	if u, _ := s.authSvc.GetUserByID(ctx, userID); u != nil {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
		out["status"] = u.Status
		out["created_at"] = u.CreatedAt
	}
	if s.idpSvc != nil {
		if p, _ := s.idpSvc.GetProfile(ctx, userID); p != nil {
			out["profile"] = p
		}
		roles, _ := s.idpSvc.GetRoleNames(ctx, userID)
		out["roles"] = roles
		groups, _ := s.idpSvc.GetGroups(ctx, userID)
		out["groups"] = groups
	}
	if s.auditSvc != nil {
		logs, _ := s.auditSvc.ListForUser(ctx, userID, 500)
		out["audit_logs"] = logs
	}
	sessions, _ := s.authSvc.ListSessions(ctx, userID)
	out["sessions"] = sessions
	return out, nil
}

func (s *AccountService) ValidateProfileUpdate(raw map[string]any) (apptypes.ProfileInput, error) {
	return s.schema.ValidateProfile(raw)
}

func (s *AccountService) ExportJSON(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	data, err := s.ExportAccount(ctx, userID)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(data, "", "  ")
}
