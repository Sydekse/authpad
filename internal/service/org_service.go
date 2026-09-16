package service

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/idp"
	idp_repo "github.com/Sydekse/authpad/internal/repository/idp"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrTenancyDisabled   = errors.New("tenancy is not enabled")
	ErrOrgNotFound       = errors.New("organization not found")
	ErrNotOrgMember      = errors.New("not a member of this organization")
	ErrOrgForbidden      = errors.New("insufficient organization role")
	ErrMembershipLimit   = errors.New("membership limit reached")
	ErrOrgCreateDisabled = errors.New("creating organizations is disabled")
	ErrInvalidSlug       = errors.New("invalid organization slug")
	ErrOrgRequired       = errors.New("organization is required")
	ErrInvalidOrgRole    = errors.New("invalid organization role")
	ErrOrgRoleExists     = errors.New("organization role already exists")
	ErrOrgNameTaken      = errors.New("name already exists")
	ErrOrgRoleReserved   = errors.New("organization role is reserved")
)

var (
	slugPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	orgRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,49}$`)
)

type OrgService struct {
	repo *idp_repo.OrgRepo
	cfg  *apptypes.AppConfig
	auth *AuthService
}

func NewOrgService(repo *idp_repo.OrgRepo, cfg *apptypes.AppConfig, auth *AuthService) *OrgService {
	return &OrgService{repo: repo, cfg: cfg, auth: auth}
}

func (s *OrgService) enabled() bool {
	return s != nil && s.cfg != nil && s.cfg.Tenancy.Enabled
}

func (s *OrgService) seedRoleDefs() []apptypes.RoleDefinition {
	roles := s.cfg.Tenancy.OrgRoles
	if len(roles) == 0 {
		return []apptypes.RoleDefinition{
			{Name: "owner", Description: "Organization owner"},
			{Name: "admin", Description: "Organization admin"},
			{Name: "member", Description: "Organization member"},
		}
	}
	return roles
}

func (s *OrgService) HasOrgRole(ctx context.Context, orgID uuid.UUID, role string) (bool, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return false, nil
	}
	return s.repo.RoleExists(ctx, orgID, role)
}

func (s *OrgService) defaultRole() string {
	if r := strings.TrimSpace(strings.ToLower(s.cfg.Tenancy.DefaultOrgRole)); r != "" {
		return r
	}
	return "member"
}

func NormalizeSlug(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, " ", "-")
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = out[:63]
		out = strings.Trim(out, "-")
	}
	return out
}

func (s *OrgService) Create(ctx context.Context, userID uuid.UUID, name, slug string, metadata map[string]any) (*idp.Organization, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	if !s.cfg.Tenancy.AllowCreateOrganization {
		return nil, ErrOrgCreateDisabled
	}
	if err := s.checkMembershipLimit(ctx, userID); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	slug = strings.TrimSpace(strings.ToLower(slug))
	if slug == "" {
		slug = NormalizeSlug(name)
	}
	if !slugPattern.MatchString(slug) {
		return nil, ErrInvalidSlug
	}
	meta, _ := json.Marshal(metadata)
	if len(meta) == 0 {
		meta = []byte("{}")
	}
	org := &idp.Organization{
		ID:        uuid.New(),
		Slug:      slug,
		Name:      name,
		Metadata:  meta,
		CreatedBy: &userID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.repo.Create(ctx, org); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrInvalidSlug
		}
		return nil, err
	}
	if err := s.repo.SeedDefaultRoles(ctx, org.ID); err != nil {
		return nil, err
	}
	if err := s.seedExtraRoles(ctx, org.ID); err != nil {
		return nil, err
	}
	if err := s.repo.AddMembership(ctx, &idp.OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		UserID:         userID,
		Role:           "owner",
		Status:         "active",
		CreatedAt:      time.Now(),
	}); err != nil {
		return nil, err
	}
	return org, nil
}

func (s *OrgService) checkMembershipLimit(ctx context.Context, userID uuid.UUID) error {
	max := s.cfg.Tenancy.MaxMembershipsPerUser
	if max <= 0 {
		return nil
	}
	n, err := s.repo.CountMemberships(ctx, userID)
	if err != nil {
		return err
	}
	if n >= max {
		return ErrMembershipLimit
	}
	return nil
}

func (s *OrgService) GetBySlug(ctx context.Context, slug string) (*idp.Organization, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	org, err := s.repo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, ErrOrgNotFound
	}
	return org, nil
}

func (s *OrgService) ListForUser(ctx context.Context, userID uuid.UUID) ([]idp.Organization, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	return s.repo.ListForUser(ctx, userID)
}

func (s *OrgService) Membership(ctx context.Context, orgID, userID uuid.UUID) (*idp.OrganizationMembership, error) {
	return s.repo.GetMembership(ctx, orgID, userID)
}

func (s *OrgService) RequireMember(ctx context.Context, orgID, userID uuid.UUID) (*idp.OrganizationMembership, error) {
	m, err := s.repo.GetMembership(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Status != "active" {
		return nil, ErrNotOrgMember
	}
	return m, nil
}

func (s *OrgService) RequireRole(ctx context.Context, orgID, userID uuid.UUID, allowed ...string) (*idp.OrganizationMembership, error) {
	m, err := s.RequireMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	for _, a := range allowed {
		if strings.EqualFold(m.Role, a) {
			return m, nil
		}
	}
	return nil, ErrOrgForbidden
}

func (s *OrgService) Update(ctx context.Context, slug string, actor uuid.UUID, name, imageURL string, metadata map[string]any) error {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		name = org.Name
	}
	if imageURL == "" {
		imageURL = org.ImageURL
	}
	meta := org.Metadata
	if metadata != nil {
		meta, _ = json.Marshal(metadata)
	}
	return s.repo.Update(ctx, slug, name, imageURL, meta)
}

func (s *OrgService) ListMembers(ctx context.Context, slug string, actor uuid.UUID) ([]idp.OrganizationMembership, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireMember(ctx, org.ID, actor); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, org.ID)
}

func (s *OrgService) Invite(ctx context.Context, slug string, actor uuid.UUID, email, role string, payload map[string]any) (rawToken string, inv *idp.OrganizationInvitation, err error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return "", nil, err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return "", nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", nil, errors.New("email is required")
	}
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		role = s.defaultRole()
	}
	ok, err := s.HasOrgRole(ctx, org.ID, role)
	if err != nil {
		return "", nil, err
	}
	if !ok || role == "owner" {
		return "", nil, ErrInvalidOrgRole
	}
	if s.cfg.Hooks.OrgInvitePolicy != nil {
		if err := s.cfg.Hooks.OrgInvitePolicy(ctx, actor, org.Slug, email, role); err != nil {
			return "", nil, err
		}
	}
	rawPayload, err := marshalPayload(payload)
	if err != nil {
		return "", nil, err
	}
	rawToken, err = security.GenerateOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	ttl := s.cfg.Invitations.TTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	inv = &idp.OrganizationInvitation{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          email,
		Role:           role,
		TokenHash:      security.HashToken(rawToken),
		Payload:        rawPayload,
		ExpiresAt:      time.Now().Add(ttl),
		InvitedBy:      &actor,
		CreatedAt:      time.Now(),
	}
	if err := s.repo.CreateInvitation(ctx, inv); err != nil {
		return "", nil, err
	}
	return rawToken, inv, nil
}

func (s *OrgService) AcceptInvite(ctx context.Context, rawToken string, userID uuid.UUID) (*idp.Organization, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	inv, err := s.repo.GetInvitationByTokenHash(ctx, security.HashToken(strings.TrimSpace(rawToken)))
	if err != nil || inv == nil {
		return nil, ErrInviteInvalid
	}
	if inv.RevokedAt != nil {
		return nil, ErrInviteRevoked
	}
	if inv.AcceptedAt != nil {
		return nil, ErrInviteUsed
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, ErrInviteInvalid
	}
	if err := s.checkMembershipLimit(ctx, userID); err != nil {
		return nil, err
	}
	deptID, levelID := extrasFromPayload(inv.Payload)
	if deptID != nil {
		ok, err := s.repo.DepartmentExists(ctx, inv.OrganizationID, *deptID)
		if err != nil {
			return nil, err
		}
		if !ok {
			deptID = nil
		}
	}
	if levelID != nil {
		ok, err := s.repo.LevelExists(ctx, inv.OrganizationID, *levelID)
		if err != nil {
			return nil, err
		}
		if !ok {
			levelID = nil
		}
	}
	if err := s.repo.AddMembership(ctx, &idp.OrganizationMembership{
		ID:             uuid.New(),
		OrganizationID: inv.OrganizationID,
		UserID:         userID,
		Role:           inv.Role,
		Status:         "active",
		DepartmentID:   deptID,
		LevelID:        levelID,
		CreatedAt:      time.Now(),
	}); err != nil {
		return nil, err
	}
	if err := s.repo.AcceptInvitation(ctx, inv.ID); err != nil {
		if errors.Is(err, idp_repo.ErrInvitationNotPending) {
			return nil, ErrInviteUsed
		}
		return nil, err
	}
	return s.repo.GetByID(ctx, inv.OrganizationID)
}

func (s *OrgService) RevokeInvite(ctx context.Context, slug string, actor, inviteID uuid.UUID) error {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return err
	}
	return s.repo.RevokeInvitation(ctx, inviteID)
}

func (s *OrgService) SwitchActive(ctx context.Context, sessionID, userID, orgID uuid.UUID) error {
	if !s.enabled() {
		return ErrTenancyDisabled
	}
	if _, err := s.RequireMember(ctx, orgID, userID); err != nil {
		return err
	}
	return s.auth.SetSessionActiveOrganization(ctx, sessionID, &orgID)
}

func (s *OrgService) ClearActive(ctx context.Context, sessionID uuid.UUID) error {
	return s.auth.SetSessionActiveOrganization(ctx, sessionID, nil)
}

func (s *OrgService) GetByID(ctx context.Context, id uuid.UUID) (*idp.Organization, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	org, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, ErrOrgNotFound
	}
	return org, nil
}

// CompleteOnSignup creates or joins an organization during signup/OAuth.
// When RequireOnSignup is set, either an invite token or an organization name is required.
func (s *OrgService) CompleteOnSignup(ctx context.Context, userID uuid.UUID, orgName, orgSlug, inviteToken string) (*idp.Organization, string, error) {
	if !s.enabled() {
		return nil, "", nil
	}
	inviteToken = strings.TrimSpace(inviteToken)
	orgName = strings.TrimSpace(orgName)
	if inviteToken != "" {
		org, err := s.AcceptInvite(ctx, inviteToken, userID)
		if err != nil {
			return nil, "", err
		}
		role := s.defaultRole()
		if m, err := s.repo.GetMembership(ctx, org.ID, userID); err == nil && m != nil {
			role = m.Role
		}
		return org, role, nil
	}
	if orgName == "" && !s.cfg.Tenancy.RequireOnSignup {
		return nil, "", nil
	}
	if orgName == "" {
		return nil, "", ErrOrgRequired
	}
	if !s.cfg.Tenancy.AllowCreateOrganization {
		if s.cfg.Tenancy.RequireOnSignup {
			return nil, "", ErrOrgRequired
		}
		return nil, "", nil
	}
	org, err := s.Create(ctx, userID, orgName, orgSlug, nil)
	if err != nil {
		return nil, "", err
	}
	return org, "owner", nil
}

func (s *OrgService) ActivePayload(ctx context.Context, userID uuid.UUID, orgID *uuid.UUID) map[string]any {
	if !s.enabled() || orgID == nil {
		return nil
	}
	org, err := s.repo.GetByID(ctx, *orgID)
	if err != nil || org == nil {
		return map[string]any{"id": orgID.String()}
	}
	role := ""
	if m, err := s.repo.GetMembership(ctx, org.ID, userID); err == nil && m != nil {
		role = m.Role
	}
	return map[string]any{
		"id":       org.ID.String(),
		"slug":     org.Slug,
		"name":     org.Name,
		"org_role": role,
	}
}

func (s *OrgService) HasMembership(ctx context.Context, userID uuid.UUID) (bool, error) {
	if !s.enabled() {
		return false, nil
	}
	n, err := s.repo.CountMemberships(ctx, userID)
	return n > 0, err
}

func FilterOrgPrivateMetadata(cfg *apptypes.AppConfig, metadata map[string]any, hasActiveOrg bool) map[string]any {
	if metadata == nil || cfg == nil || !cfg.Tenancy.Enabled || hasActiveOrg {
		return metadata
	}
	keys := cfg.Tenancy.OrgPrivateMetadataKeys
	if len(keys) == 0 {
		return metadata
	}
	out := make(map[string]any, len(metadata))
	for k, v := range metadata {
		out[k] = v
	}
	for _, k := range keys {
		delete(out, k)
	}
	return out
}

func (s *OrgService) seedExtraRoles(ctx context.Context, orgID uuid.UUID) error {
	for _, def := range s.seedRoleDefs() {
		name := strings.TrimSpace(strings.ToLower(def.Name))
		if name == "" || name == "owner" || name == "admin" || name == "member" {
			continue
		}
		if !orgRolePattern.MatchString(name) {
			continue
		}
		desc := strings.TrimSpace(def.Description)
		if desc == "" {
			desc = name
		}
		err := s.repo.CreateRole(ctx, &idp.OrganizationRole{
			ID:             uuid.New(),
			OrganizationID: orgID,
			Name:           name,
			Description:    desc,
			CreatedAt:      time.Now(),
		})
		if err != nil && !isUniqueViolation(err) {
			return err
		}
	}
	return nil
}

// Ensure returns the organization with slug, creating it when missing.
// createdBy, when not uuid.Nil, is added (or promoted) as owner.
func (s *OrgService) Ensure(ctx context.Context, slug, name string, createdBy uuid.UUID) (*idp.Organization, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	slug = strings.TrimSpace(strings.ToLower(slug))
	if !slugPattern.MatchString(slug) {
		return nil, ErrInvalidSlug
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = slug
	}
	org, err := s.repo.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if org == nil {
		org = &idp.Organization{
			ID:        uuid.New(),
			Slug:      slug,
			Name:      name,
			Metadata:  json.RawMessage(`{}`),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if createdBy != uuid.Nil {
			org.CreatedBy = &createdBy
		}
		if err := s.repo.Create(ctx, org); err != nil {
			if isUniqueViolation(err) {
				org, err = s.repo.GetBySlug(ctx, slug)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		}
	}
	if err := s.repo.SeedDefaultRoles(ctx, org.ID); err != nil {
		return nil, err
	}
	if err := s.seedExtraRoles(ctx, org.ID); err != nil {
		return nil, err
	}
	if createdBy != uuid.Nil {
		if err := s.repo.AddMembership(ctx, &idp.OrganizationMembership{
			ID:             uuid.New(),
			OrganizationID: org.ID,
			UserID:         createdBy,
			Role:           "owner",
			Status:         "active",
			CreatedAt:      time.Now(),
		}); err != nil {
			return nil, err
		}
	}
	return org, nil
}

func (s *OrgService) CreateRole(ctx context.Context, orgID uuid.UUID, name, description string) (*idp.OrganizationRole, error) {
	if !s.enabled() {
		return nil, ErrTenancyDisabled
	}
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "owner" {
		return nil, ErrOrgRoleReserved
	}
	if !orgRolePattern.MatchString(name) {
		return nil, ErrInvalidOrgRole
	}
	description = strings.TrimSpace(description)
	if description == "" {
		description = name
	}
	role := &idp.OrganizationRole{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Name:           name,
		Description:    description,
		CreatedAt:      time.Now(),
	}
	if err := s.repo.CreateRole(ctx, role); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrOrgRoleExists
		}
		return nil, err
	}
	return role, nil
}

func (s *OrgService) ListRoles(ctx context.Context, slug string, actor uuid.UUID) ([]idp.OrganizationRole, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireMember(ctx, org.ID, actor); err != nil {
		return nil, err
	}
	return s.repo.ListRoles(ctx, org.ID)
}

func (s *OrgService) CreateRoleForActor(ctx context.Context, slug string, actor uuid.UUID, name, description string) (*idp.OrganizationRole, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner"); err != nil {
		return nil, err
	}
	return s.CreateRole(ctx, org.ID, name, description)
}

func (s *OrgService) CreateDepartment(ctx context.Context, orgID uuid.UUID, name string) (*idp.OrganizationDepartment, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	d := &idp.OrganizationDepartment{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Name:           name,
		CreatedAt:      time.Now(),
	}
	if err := s.repo.CreateDepartment(ctx, d); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrOrgNameTaken
		}
		return nil, err
	}
	return d, nil
}

func (s *OrgService) ListDepartments(ctx context.Context, slug string, actor uuid.UUID) ([]idp.OrganizationDepartment, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireMember(ctx, org.ID, actor); err != nil {
		return nil, err
	}
	return s.repo.ListDepartments(ctx, org.ID)
}

func (s *OrgService) CreateDepartmentForActor(ctx context.Context, slug string, actor uuid.UUID, name string) (*idp.OrganizationDepartment, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return nil, err
	}
	return s.CreateDepartment(ctx, org.ID, name)
}

func (s *OrgService) DeleteDepartment(ctx context.Context, slug string, actor, id uuid.UUID) error {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return err
	}
	n, err := s.repo.DeleteDepartment(ctx, org.ID, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrOrgNotFound
	}
	return nil
}

func (s *OrgService) CreateLevel(ctx context.Context, orgID uuid.UUID, name string) (*idp.OrganizationLevel, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	l := &idp.OrganizationLevel{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Name:           name,
		CreatedAt:      time.Now(),
	}
	if err := s.repo.CreateLevel(ctx, l); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrOrgNameTaken
		}
		return nil, err
	}
	return l, nil
}

func (s *OrgService) ListLevels(ctx context.Context, slug string, actor uuid.UUID) ([]idp.OrganizationLevel, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireMember(ctx, org.ID, actor); err != nil {
		return nil, err
	}
	return s.repo.ListLevels(ctx, org.ID)
}

func (s *OrgService) CreateLevelForActor(ctx context.Context, slug string, actor uuid.UUID, name string) (*idp.OrganizationLevel, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return nil, err
	}
	return s.CreateLevel(ctx, org.ID, name)
}

func (s *OrgService) DeleteLevel(ctx context.Context, slug string, actor, id uuid.UUID) error {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return err
	}
	n, err := s.repo.DeleteLevel(ctx, org.ID, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrOrgNotFound
	}
	return nil
}

func (s *OrgService) ListInvitations(ctx context.Context, slug string, actor uuid.UUID) ([]idp.OrganizationInvitation, error) {
	org, err := s.GetBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if _, err := s.RequireRole(ctx, org.ID, actor, "owner", "admin"); err != nil {
		return nil, err
	}
	return s.repo.ListInvitations(ctx, org.ID)
}

func (s *OrgService) PeekInvitation(ctx context.Context, rawToken string) (*idp.OrganizationInvitation, *idp.Organization, error) {
	if !s.enabled() {
		return nil, nil, ErrTenancyDisabled
	}
	inv, err := s.repo.GetInvitationByTokenHash(ctx, security.HashToken(strings.TrimSpace(rawToken)))
	if err != nil || inv == nil {
		return nil, nil, ErrInviteInvalid
	}
	if inv.RevokedAt != nil {
		return nil, nil, ErrInviteRevoked
	}
	if inv.AcceptedAt != nil {
		return nil, nil, ErrInviteUsed
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, nil, ErrInviteInvalid
	}
	org, err := s.repo.GetByID(ctx, inv.OrganizationID)
	if err != nil {
		return nil, nil, err
	}
	return inv, org, nil
}

func marshalPayload(payload map[string]any) (json.RawMessage, error) {
	if len(payload) == 0 {
		return json.RawMessage(`{}`), nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func extrasFromPayload(raw json.RawMessage) (deptID, levelID *uuid.UUID) {
	if len(raw) == 0 {
		return nil, nil
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil
	}
	return uuidFromMap(p, "department_id"), uuidFromMap(p, "level_id")
}

func uuidFromMap(p map[string]any, key string) *uuid.UUID {
	v, ok := p[key]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
