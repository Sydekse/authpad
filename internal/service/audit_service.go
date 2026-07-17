package service

import (
	"context"

	auth_repo "github.com/auth-project/authpad/internal/repository/auth"
	idp_repo "github.com/auth-project/authpad/internal/repository/idp"
	"github.com/google/uuid"
)

// AuditService writes audit logs to auth and idp databases.
type AuditService struct {
	authRepo *auth_repo.AuditRepo
	idpRepo  *idp_repo.AuditRepo
}

func NewAuditService(authRepo *auth_repo.AuditRepo, idpRepo *idp_repo.AuditRepo) *AuditService {
	return &AuditService{authRepo: authRepo, idpRepo: idpRepo}
}

func (s *AuditService) LogAuth(ctx context.Context, userID *uuid.UUID, action, ip, ua string, details map[string]any) {
	if s.authRepo != nil {
		_ = s.authRepo.Log(ctx, userID, action, ip, ua, details)
	}
}

func (s *AuditService) LogIdP(ctx context.Context, userID *uuid.UUID, action string, details map[string]any) {
	if s.idpRepo != nil {
		_ = s.idpRepo.Log(ctx, userID, action, details)
	}
}

func (s *AuditService) ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]map[string]any, error) {
	var out []map[string]any
	if s.authRepo != nil {
		items, err := s.authRepo.ListByUserID(ctx, userID, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	if s.idpRepo != nil {
		items, err := s.idpRepo.ListByUserID(ctx, userID, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (s *AuditService) ListRecentAdmin(ctx context.Context, limit int) ([]map[string]any, error) {
	var out []map[string]any
	if s.authRepo != nil {
		items, _ := s.authRepo.ListRecent(ctx, limit)
		out = append(out, items...)
	}
	if s.idpRepo != nil {
		items, _ := s.idpRepo.ListRecent(ctx, limit)
		out = append(out, items...)
	}
	return out, nil
}
