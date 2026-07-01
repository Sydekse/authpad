package idp

import (
	"context"

	"github.com/auth-project/goauth/internal/database"
	"github.com/auth-project/goauth/internal/domain/idp"
	"github.com/google/uuid"
)

// GroupRepo handles groups and user_groups in IdP DB.
type GroupRepo struct {
	db *database.IdPDB
}

// NewGroupRepo returns a new GroupRepo.
func NewGroupRepo(db *database.IdPDB) *GroupRepo {
	return &GroupRepo{db: db}
}

// GetByUserID returns groups for a user (group info + membership).
func (r *GroupRepo) GetByUserID(ctx context.Context, userID uuid.UUID) ([]idp.Group, error) {
	rows, err := r.db.Query(ctx, `
		SELECT g.id, g.name, COALESCE(g.description, ''), COALESCE(g.group_type, ''), COALESCE(g.metadata, '{}'), g.created_at
		FROM user_groups ug JOIN groups g ON ug.group_id = g.id WHERE ug.user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []idp.Group
	for rows.Next() {
		var g idp.Group
		err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.GroupType, &g.Metadata, &g.CreatedAt)
		if err != nil {
			return nil, err
		}
		list = append(list, g)
	}
	return list, rows.Err()
}

// Create inserts a new group.
func (r *GroupRepo) Create(ctx context.Context, g *idp.Group) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO groups (id, name, description, group_type, metadata, created_at)
		VALUES ($1, $2, $3, $4, COALESCE($5, '{}'), $6)
	`, g.ID, g.Name, g.Description, g.GroupType, g.Metadata, g.CreatedAt)
	return err
}

// AddMember adds a user to a group.
func (r *GroupRepo) AddMember(ctx context.Context, groupID, userID uuid.UUID, addedBy *uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_groups (id, user_id, group_id, joined_at, added_by)
		VALUES (gen_random_uuid(), $1, $2, NOW(), $3)
		ON CONFLICT (user_id, group_id) DO NOTHING
	`, userID, groupID, addedBy)
	return err
}

// RemoveMember removes a user from a group.
func (r *GroupRepo) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM user_groups WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	return err
}
