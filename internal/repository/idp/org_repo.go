package idp

import (
	"context"
	"encoding/json"

	"github.com/Sydekse/authpad/internal/database"
	"github.com/Sydekse/authpad/internal/domain/idp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type OrgRepo struct {
	db *database.IdPDB
}

func NewOrgRepo(db *database.IdPDB) *OrgRepo {
	return &OrgRepo{db: db}
}

func (r *OrgRepo) Create(ctx context.Context, o *idp.Organization) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO organizations (id, slug, name, image_url, metadata, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
	`, o.ID, o.Slug, o.Name, o.ImageURL, o.Metadata, o.CreatedBy, o.CreatedAt)
	return err
}

func (r *OrgRepo) GetBySlug(ctx context.Context, slug string) (*idp.Organization, error) {
	return r.scanOrg(ctx, `SELECT id, slug, name, COALESCE(image_url, ''), COALESCE(metadata, '{}'), created_by, created_at, updated_at FROM organizations WHERE slug = $1`, slug)
}

func (r *OrgRepo) GetByID(ctx context.Context, id uuid.UUID) (*idp.Organization, error) {
	return r.scanOrg(ctx, `SELECT id, slug, name, COALESCE(image_url, ''), COALESCE(metadata, '{}'), created_by, created_at, updated_at FROM organizations WHERE id = $1`, id)
}

func (r *OrgRepo) Update(ctx context.Context, slug, name, imageURL string, metadata []byte) error {
	_, err := r.db.Exec(ctx, `
		UPDATE organizations SET name = $2, image_url = $3, metadata = $4, updated_at = NOW() WHERE slug = $1
	`, slug, name, imageURL, metadata)
	return err
}

func (r *OrgRepo) ListForUser(ctx context.Context, userID uuid.UUID) ([]idp.Organization, error) {
	rows, err := r.db.Query(ctx, `
		SELECT o.id, o.slug, o.name, COALESCE(o.image_url, ''), COALESCE(o.metadata, '{}'), o.created_by, o.created_at, o.updated_at
		FROM organizations o
		JOIN organization_memberships m ON m.organization_id = o.id
		WHERE m.user_id = $1 AND m.status = 'active'
		ORDER BY o.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []idp.Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

func (r *OrgRepo) AddMembership(ctx context.Context, m *idp.OrganizationMembership) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO organization_memberships (id, organization_id, user_id, role, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status
	`, m.ID, m.OrganizationID, m.UserID, m.Role, m.Status, m.CreatedAt)
	return err
}

func (r *OrgRepo) GetMembership(ctx context.Context, orgID, userID uuid.UUID) (*idp.OrganizationMembership, error) {
	var m idp.OrganizationMembership
	err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, user_id, role, status, created_at
		FROM organization_memberships WHERE organization_id = $1 AND user_id = $2
	`, orgID, userID).Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.Role, &m.Status, &m.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

func (r *OrgRepo) CountMemberships(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM organization_memberships WHERE user_id = $1 AND status = 'active'`, userID).Scan(&n)
	return n, err
}

func (r *OrgRepo) ListMembers(ctx context.Context, orgID uuid.UUID) ([]idp.OrganizationMembership, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, organization_id, user_id, role, status, created_at
		FROM organization_memberships WHERE organization_id = $1 AND status = 'active' ORDER BY created_at
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []idp.OrganizationMembership
	for rows.Next() {
		var m idp.OrganizationMembership
		if err := rows.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.Role, &m.Status, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *OrgRepo) CreateInvitation(ctx context.Context, inv *idp.OrganizationInvitation) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, expires_at, invited_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, inv.ID, inv.OrganizationID, inv.Email, inv.Role, inv.TokenHash, inv.ExpiresAt, inv.InvitedBy, inv.CreatedAt)
	return err
}

func (r *OrgRepo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*idp.OrganizationInvitation, error) {
	var inv idp.OrganizationInvitation
	err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, email, role, token_hash, expires_at, invited_by, accepted_at, revoked_at, created_at
		FROM organization_invitations WHERE token_hash = $1
	`, tokenHash).Scan(&inv.ID, &inv.OrganizationID, &inv.Email, &inv.Role, &inv.TokenHash, &inv.ExpiresAt, &inv.InvitedBy, &inv.AcceptedAt, &inv.RevokedAt, &inv.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &inv, nil
}

func (r *OrgRepo) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	res, err := r.db.Exec(ctx, `UPDATE organization_invitations SET accepted_at = NOW() WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvitationNotPending
	}
	return nil
}

func (r *OrgRepo) RevokeInvitation(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE organization_invitations SET revoked_at = NOW() WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`, id)
	return err
}

func (r *OrgRepo) scanOrg(ctx context.Context, q string, arg any) (*idp.Organization, error) {
	row := r.db.QueryRow(ctx, q, arg)
	o, err := scanOrg(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

func scanOrg(row rowScanner) (*idp.Organization, error) {
	var o idp.Organization
	var meta []byte
	if err := row.Scan(&o.ID, &o.Slug, &o.Name, &o.ImageURL, &meta, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, err
	}
	if len(meta) == 0 {
		meta = []byte("{}")
	}
	o.Metadata = json.RawMessage(meta)
	return &o, nil
}
