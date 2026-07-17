package idp

import (
	"context"

	"github.com/auth-project/authpad/internal/database"
	"github.com/auth-project/authpad/internal/domain/idp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProfileRepo handles users_profile table in IdP DB.
type ProfileRepo struct {
	db *database.IdPDB
}

// NewProfileRepo returns a new ProfileRepo.
func NewProfileRepo(db *database.IdPDB) *ProfileRepo {
	return &ProfileRepo{db: db}
}

// Create inserts a user profile.
func (r *ProfileRepo) Create(ctx context.Context, p *idp.UserProfile) error {
	metadata := p.Metadata
	if metadata == nil || len(metadata) == 0 {
		metadata = []byte("{}")
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO users_profile (user_id, name, image_url, bio, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
	`, p.UserID, p.Name, p.ImageURL, p.Bio, metadata, p.CreatedAt, p.UpdatedAt)
	return err
}

// GetByUserID returns a profile by user_id.
func (r *ProfileRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*idp.UserProfile, error) {
	var p idp.UserProfile
	err := r.db.QueryRow(ctx, `
		SELECT user_id, name, COALESCE(image_url, ''), COALESCE(bio, ''), COALESCE(metadata, '{}'), created_at, updated_at
		FROM users_profile WHERE user_id = $1
	`, userID).Scan(&p.UserID, &p.Name, &p.ImageURL, &p.Bio, &p.Metadata, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

// Update updates name, image_url, bio, metadata.
func (r *ProfileRepo) Update(ctx context.Context, userID uuid.UUID, name, imageURL, bio string, metadata []byte) error {
	if metadata == nil || len(metadata) == 0 {
		metadata = []byte("{}")
	}
	_, err := r.db.Exec(ctx, `
		UPDATE users_profile SET name = COALESCE(NULLIF($1, ''), name), image_url = COALESCE(NULLIF($2, ''), image_url), bio = COALESCE(NULLIF($3, ''), bio), metadata = COALESCE(NULLIF($4::jsonb, '{}'::jsonb), metadata), updated_at = NOW()
		WHERE user_id = $5
	`, name, imageURL, bio, metadata, userID)
	return err
}

// Anonymize clears profile data for GDPR deletion.
func (r *ProfileRepo) Anonymize(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users_profile SET name = 'Deleted User', image_url = NULL, bio = NULL, metadata = '{}', updated_at = NOW()
		WHERE user_id = $1
	`, userID)
	return err
}

// Delete removes a profile (used for signup rollback).
func (r *ProfileRepo) Delete(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM users_profile WHERE user_id = $1`, userID)
	return err
}
