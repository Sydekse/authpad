package auth

import (
	"context"
	"errors"

	"github.com/Sydekse/authpad/internal/domain/idp"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/google/uuid"
)

var (
	ErrTenancyDisabled   = service.ErrTenancyDisabled
	ErrOrgNotFound       = service.ErrOrgNotFound
	ErrNotOrgMember      = service.ErrNotOrgMember
	ErrOrgForbidden      = service.ErrOrgForbidden
	ErrMembershipLimit   = service.ErrMembershipLimit
	ErrOrgCreateDisabled = service.ErrOrgCreateDisabled
	ErrInvalidSlug       = service.ErrInvalidSlug
	ErrOrgRequired       = service.ErrOrgRequired
	ErrInvalidOrgRole    = service.ErrInvalidOrgRole
	ErrOrgRoleExists     = service.ErrOrgRoleExists
	ErrOrgNameTaken      = service.ErrOrgNameTaken
	ErrOrgRoleReserved   = service.ErrOrgRoleReserved
	ErrInviteInvalid     = service.ErrInviteInvalid
	ErrInviteRevoked     = service.ErrInviteRevoked
	ErrInviteUsed        = service.ErrInviteUsed
)

type (
	Organization           = idp.Organization
	OrganizationMembership = idp.OrganizationMembership
	OrganizationInvitation = idp.OrganizationInvitation
	OrganizationRole       = idp.OrganizationRole
	OrganizationDepartment = idp.OrganizationDepartment
	OrganizationLevel      = idp.OrganizationLevel
)

func (a *Auth) orgSvc() (*service.OrgService, error) {
	if a == nil || a.srv == nil || a.srv.OrgSvc == nil {
		return nil, errors.New("tenancy is not enabled")
	}
	return a.srv.OrgSvc, nil
}

func (a *Auth) EnsureOrganization(ctx context.Context, slug, name string, createdBy uuid.UUID) (*Organization, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.Ensure(ctx, slug, name, createdBy)
}

func (a *Auth) CreateOrganization(ctx context.Context, userID uuid.UUID, name, slug string, metadata map[string]any) (*Organization, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.Create(ctx, userID, name, slug, metadata)
}

func (a *Auth) GetOrganization(ctx context.Context, id uuid.UUID) (*Organization, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.GetByID(ctx, id)
}

func (a *Auth) ListOrgMembers(ctx context.Context, slug string, actor uuid.UUID) ([]OrganizationMembership, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.ListMembers(ctx, slug, actor)
}

func (a *Auth) ListOrganizations(ctx context.Context, userID uuid.UUID) ([]Organization, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.ListForUser(ctx, userID)
}

func (a *Auth) SwitchActiveOrganization(ctx context.Context, sessionID, userID, orgID uuid.UUID) error {
	s, err := a.orgSvc()
	if err != nil {
		return err
	}
	return s.SwitchActive(ctx, sessionID, userID, orgID)
}

func (a *Auth) ClearActiveOrganization(ctx context.Context, sessionID uuid.UUID) error {
	s, err := a.orgSvc()
	if err != nil {
		return err
	}
	return s.ClearActive(ctx, sessionID)
}

func (a *Auth) CreateOrgRole(ctx context.Context, orgID uuid.UUID, name, description string) (*OrganizationRole, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.CreateRole(ctx, orgID, name, description)
}

func (a *Auth) ListOrgRoles(ctx context.Context, slug string, actor uuid.UUID) ([]OrganizationRole, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.ListRoles(ctx, slug, actor)
}

func (a *Auth) CreateDepartment(ctx context.Context, orgID uuid.UUID, name string) (*OrganizationDepartment, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.CreateDepartment(ctx, orgID, name)
}

func (a *Auth) ListDepartments(ctx context.Context, slug string, actor uuid.UUID) ([]OrganizationDepartment, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.ListDepartments(ctx, slug, actor)
}

func (a *Auth) CreateLevel(ctx context.Context, orgID uuid.UUID, name string) (*OrganizationLevel, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.CreateLevel(ctx, orgID, name)
}

func (a *Auth) ListLevels(ctx context.Context, slug string, actor uuid.UUID) ([]OrganizationLevel, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.ListLevels(ctx, slug, actor)
}

func (a *Auth) InviteToOrganization(ctx context.Context, slug string, actor uuid.UUID, email, role string, payload map[string]any) (rawToken string, inv *OrganizationInvitation, err error) {
	s, err := a.orgSvc()
	if err != nil {
		return "", nil, err
	}
	return s.Invite(ctx, slug, actor, email, role, payload)
}

func (a *Auth) AcceptOrganizationInvite(ctx context.Context, rawToken string, userID uuid.UUID) (*Organization, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.AcceptInvite(ctx, rawToken, userID)
}

func (a *Auth) PeekOrganizationInvite(ctx context.Context, rawToken string) (*OrganizationInvitation, *Organization, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, nil, err
	}
	return s.PeekInvitation(ctx, rawToken)
}

func (a *Auth) RequireOrgMember(ctx context.Context, slug string, userID uuid.UUID) (*OrganizationMembership, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	return s.RequireMember(ctx, org.ID, userID)
}

func (a *Auth) RequireOrgRole(ctx context.Context, slug string, userID uuid.UUID, roles ...string) (*OrganizationMembership, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	return s.RequireRole(ctx, org.ID, userID, roles...)
}
