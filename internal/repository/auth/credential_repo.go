package auth

import (
	"context"

	"github.com/auth-project/authpad/internal/database"
	"github.com/auth-project/authpad/internal/domain/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CredentialRepo handles credentials table in Auth DB.
type CredentialRepo struct {
	db *database.AuthDB
}

// NewCredentialRepo returns a new CredentialRepo.
func NewCredentialRepo(db *database.AuthDB) *CredentialRepo {
	return &CredentialRepo{db: db}
}

// Create inserts a credential.
func (r *CredentialRepo) Create(ctx context.Context, c *auth.Credential) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO credentials (id, user_id, credential_type, password_hash, hash_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, c.ID, c.UserID, c.CredentialType, c.PasswordHash, c.HashVersion, c.CreatedAt, c.UpdatedAt)
	return err
}

// GetByUserID returns the password credential for a user (if any).
func (r *CredentialRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (*auth.Credential, error) {
	var c auth.Credential
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, credential_type, password_hash, hash_version, created_at, updated_at
		FROM credentials WHERE user_id = $1 AND credential_type = 'password'
	`, userID).Scan(&c.ID, &c.UserID, &c.CredentialType, &c.PasswordHash, &c.HashVersion, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}

// UpdateHash updates the password hash and hash_version for a credential.
func (r *CredentialRepo) UpdateHash(ctx context.Context, id uuid.UUID, passwordHash string, hashVersion int) error {
	_, err := r.db.Exec(ctx, `
		UPDATE credentials SET password_hash = $1, hash_version = $2, updated_at = NOW() WHERE id = $3
	`, passwordHash, hashVersion, id)
	return err
}

// DeleteByUserID removes credentials for a user.
func (r *CredentialRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1`, userID)
	return err
}
