package auth

import (
	"context"
	"time"

	"github.com/Sydekse/authpad/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MagicLinkToken is a stored magic-link record. The raw token is never stored.
type MagicLinkToken struct {
	ID             uuid.UUID
	TokenHash      string
	OrganizationID uuid.UUID
	Email          string
	RedirectTo     string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// MagicLinkRepo handles magic_link_tokens in the Auth DB.
type MagicLinkRepo struct {
	db *database.AuthDB
}

func NewMagicLinkRepo(db *database.AuthDB) *MagicLinkRepo {
	return &MagicLinkRepo{db: db}
}

func (r *MagicLinkRepo) Create(ctx context.Context, t *MagicLinkToken) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO magic_link_tokens (id, token_hash, organization_id, email, redirect_to, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, t.ID, t.TokenHash, t.OrganizationID, t.Email, t.RedirectTo, t.CreatedAt, t.ExpiresAt)
	return err
}

// Consume atomically marks a live, unconsumed token as used and returns it.
// When orgID is non-nil the token must have been issued for that organization;
// a mismatch leaves the token untouched. It returns nil, nil when no row matched.
func (r *MagicLinkRepo) Consume(ctx context.Context, tokenHash string, orgID *uuid.UUID) (*MagicLinkToken, error) {
	var t MagicLinkToken
	err := r.db.QueryRow(ctx, `
		UPDATE magic_link_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
		  AND ($2::uuid IS NULL OR organization_id = $2::uuid)
		RETURNING id, token_hash, organization_id, email, redirect_to, created_at, expires_at
	`, tokenHash, orgID).Scan(&t.ID, &t.TokenHash, &t.OrganizationID, &t.Email, &t.RedirectTo, &t.CreatedAt, &t.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// DeleteExpired removes tokens that expired before the given time.
func (r *MagicLinkRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.Exec(ctx, `DELETE FROM magic_link_tokens WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
