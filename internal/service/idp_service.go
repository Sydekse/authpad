package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/auth-project/goauth/internal/domain/idp"
	idp_repo "github.com/auth-project/goauth/internal/repository/idp"
	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/google/uuid"
)

// IdPService handles identity data (IdP DB only).
type IdPService struct {
	profileRepo      *idp_repo.ProfileRepo
	roleRepo         *idp_repo.RoleRepo
	groupRepo        *idp_repo.GroupRepo
	auditRepo        *idp_repo.AuditRepo
	roles            []apptypes.RoleDefinition
	onRoleAssigned   func(ctx context.Context, userID uuid.UUID, role string) error
}

func NewIdPService(
	profileRepo *idp_repo.ProfileRepo,
	roleRepo *idp_repo.RoleRepo,
	groupRepo *idp_repo.GroupRepo,
	auditRepo *idp_repo.AuditRepo,
	roles []apptypes.RoleDefinition,
	onRoleAssigned func(ctx context.Context, userID uuid.UUID, role string) error,
) *IdPService {
	return &IdPService{
		profileRepo:    profileRepo,
		roleRepo:       roleRepo,
		groupRepo:      groupRepo,
		auditRepo:      auditRepo,
		roles:          roles,
		onRoleAssigned: onRoleAssigned,
	}
}

func (s *IdPService) SeedRoles(ctx context.Context) error {
	for _, role := range s.roles {
		name := strings.TrimSpace(strings.ToLower(role.Name))
		if name == "" {
			continue
		}
		if err := s.roleRepo.UpsertRole(ctx, name, role.Description); err != nil {
			return err
		}
	}
	return nil
}

func (s *IdPService) AllowedRoles() []string {
	out := make([]string, 0, len(s.roles))
	for _, role := range s.roles {
		name := strings.TrimSpace(strings.ToLower(role.Name))
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func (s *IdPService) IsAllowedRole(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, role := range s.roles {
		if strings.EqualFold(role.Name, name) {
			return true
		}
	}
	return false
}

func (s *IdPService) CreateProfile(ctx context.Context, userID uuid.UUID, profile apptypes.ProfileInput) error {
	now := time.Now()
	metadata, _ := json.Marshal(profile.Metadata)
	p := &idp.UserProfile{
		UserID:    userID,
		Name:      profile.Name,
		ImageURL:  profile.ImageURL,
		Bio:       profile.Bio,
		Metadata:  metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return s.profileRepo.Create(ctx, p)
}

func (s *IdPService) GetProfile(ctx context.Context, userID uuid.UUID) (*idp.UserProfile, error) {
	return s.profileRepo.GetByUserID(ctx, userID)
}

func (s *IdPService) GetRoleNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.roleRepo.GetRoleNamesByUserID(ctx, userID)
}

func (s *IdPService) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return s.roleRepo.HasRole(ctx, userID, strings.ToLower(roleName))
}

func (s *IdPService) AssignRoleByName(ctx context.Context, userID uuid.UUID, roleName string) error {
	roleName = strings.TrimSpace(strings.ToLower(roleName))
	if !s.IsAllowedRole(roleName) {
		return fmt.Errorf("role not allowed: %s", roleName)
	}
	role, err := s.roleRepo.GetByName(ctx, roleName)
	if err != nil || role == nil {
		return fmt.Errorf("role not found: %s", roleName)
	}
	if err := s.roleRepo.AssignRole(ctx, userID, role.ID, nil); err != nil {
		return err
	}
	if s.auditRepo != nil {
		_ = s.auditRepo.Log(ctx, &userID, "role.assigned", map[string]any{"role": roleName})
	}
	if s.onRoleAssigned != nil {
		return s.onRoleAssigned(ctx, userID, roleName)
	}
	return nil
}

func (s *IdPService) RevokeRoleByName(ctx context.Context, userID uuid.UUID, roleName string) error {
	roleName = strings.TrimSpace(strings.ToLower(roleName))
	if err := s.roleRepo.RevokeRole(ctx, userID, roleName); err != nil {
		return err
	}
	if s.auditRepo != nil {
		_ = s.auditRepo.Log(ctx, &userID, "role.revoked", map[string]any{"role": roleName})
	}
	return nil
}

func (s *IdPService) GetGroups(ctx context.Context, userID uuid.UUID) ([]idp.Group, error) {
	return s.groupRepo.GetByUserID(ctx, userID)
}

func (s *IdPService) UpdateProfile(ctx context.Context, userID uuid.UUID, profile apptypes.ProfileInput) error {
	metadata, _ := json.Marshal(profile.Metadata)
	return s.profileRepo.Update(ctx, userID, profile.Name, profile.ImageURL, profile.Bio, metadata)
}

func (s *IdPService) CreateGroup(ctx context.Context, name, description, groupType string, metadata map[string]any) (*idp.Group, error) {
	meta, _ := json.Marshal(metadata)
	g := &idp.Group{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
		GroupType:   groupType,
		Metadata:    meta,
		CreatedAt:   time.Now(),
	}
	if err := s.groupRepo.Create(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

func (s *IdPService) AddGroupMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error {
	return s.groupRepo.AddMember(ctx, groupID, userID, addedBy)
}

func (s *IdPService) RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return s.groupRepo.RemoveMember(ctx, groupID, userID)
}

func (s *IdPService) DeleteProfile(ctx context.Context, userID uuid.UUID) error {
	return s.profileRepo.Anonymize(ctx, userID)
}

func (s *IdPService) RollbackProfile(ctx context.Context, userID uuid.UUID) error {
	return s.profileRepo.Delete(ctx, userID)
}
