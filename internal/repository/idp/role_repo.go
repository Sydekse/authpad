package idp

import (
	"context"

	"github.com/auth-project/authpad/internal/database"
	"github.com/auth-project/authpad/internal/domain/idp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RoleRepo handles roles and user_roles in IdP DB.
type RoleRepo struct {
	db *database.IdPDB
}

// NewRoleRepo returns a new RoleRepo.
func NewRoleRepo(db *database.IdPDB) *RoleRepo {
	return &RoleRepo{db: db}
}

// GetByName returns a role by name.
func (r *RoleRepo) GetByName(ctx context.Context, name string) (*idp.Role, error) {
	var ro idp.Role
	err := r.db.QueryRow(ctx, `SELECT id, name, COALESCE(description, ''), created_at FROM roles WHERE name = $1`, name).Scan(&ro.ID, &ro.Name, &ro.Description, &ro.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &ro, nil
}

// AssignRole adds a user_role row (idempotent with UNIQUE constraint).
func (r *RoleRepo) AssignRole(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_roles (id, user_id, role_id, assigned_at, assigned_by)
		VALUES (gen_random_uuid(), $1, $2, NOW(), $3)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, roleID, assignedBy)
	return err
}

// GetRoleNamesByUserID returns role names for a user.
func (r *RoleRepo) GetRoleNamesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// UpsertRole creates or updates a role definition.
func (r *RoleRepo) UpsertRole(ctx context.Context, name, description string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO roles (id, name, description) VALUES (gen_random_uuid(), $1, $2)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
	`, name, description)
	return err
}

// RevokeRole removes a role assignment from a user.
func (r *RoleRepo) RevokeRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM user_roles ur USING roles r
		WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.name = $2
	`, userID, roleName)
	return err
}

// HasRole returns true if user has the named role.
func (r *RoleRepo) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1 AND r.name = $2
		)
	`, userID, roleName).Scan(&exists)
	return exists, err
}
