package auth

import (
	"context"
	"time"

	"github.com/auth-project/authpad/internal/database"
	"github.com/auth-project/authpad/internal/domain/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PasswordResetTokenRepo handles password_reset_tokens table in Auth DB.
type PasswordResetTokenRepo struct {
	db *database.AuthDB
}

// NewPasswordResetTokenRepo returns a new PasswordResetTokenRepo.
func NewPasswordResetTokenRepo(db *database.AuthDB) *PasswordResetTokenRepo {
	return &PasswordResetTokenRepo{db: db}
}

// Create inserts a password reset token.
func (r *PasswordResetTokenRepo) Create(ctx context.Context, t *auth.PasswordResetToken) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.CreatedAt)
	return err
}

// GetByTokenHash returns the token record if found and not expired.
func (r *PasswordResetTokenRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*auth.PasswordResetToken, error) {
	var t auth.PasswordResetToken
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1 AND expires_at > NOW()
	`, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// DeleteByID removes a token (after successful reset).
func (r *PasswordResetTokenRepo) DeleteByID(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM password_reset_tokens WHERE id = $1`, id)
	return err
}

// DeleteExpired removes expired tokens (can be called by a job).
func (r *PasswordResetTokenRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
