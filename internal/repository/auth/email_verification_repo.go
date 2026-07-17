package auth

import (
	"context"
	"time"

	"github.com/auth-project/authpad/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EmailVerificationRepo manages email verification tokens.
type EmailVerificationRepo struct {
	db *database.AuthDB
}

func NewEmailVerificationRepo(db *database.AuthDB) *EmailVerificationRepo {
	return &EmailVerificationRepo{db: db}
}

func (r *EmailVerificationRepo) Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM email_verification_tokens WHERE user_id = $1`, userID); err != nil {
		return err
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)
	`, uuid.New(), userID, tokenHash, expiresAt)
	return err
}

func (r *EmailVerificationRepo) GetByTokenHash(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := r.db.QueryRow(ctx, `
		SELECT user_id FROM email_verification_tokens WHERE token_hash = $1 AND expires_at > NOW()
	`, tokenHash).Scan(&userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, nil
		}
		return uuid.Nil, err
	}
	return userID, nil
}

func (r *EmailVerificationRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM email_verification_tokens WHERE user_id = $1`, userID)
	return err
}
