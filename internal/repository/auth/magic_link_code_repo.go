package auth

import (
	"context"
	"time"

	"github.com/Sydekse/authpad/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MagicLinkCode is a stored one-time exchange code. The raw code is never stored.
type MagicLinkCode struct {
	ID             uuid.UUID
	CodeHash       string
	SessionID      uuid.UUID
	OrganizationID uuid.UUID
	RedirectOrigin string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// MagicLinkCodeRepo handles magic_link_codes in the Auth DB.
type MagicLinkCodeRepo struct {
	db *database.AuthDB
}

func NewMagicLinkCodeRepo(db *database.AuthDB) *MagicLinkCodeRepo {
	return &MagicLinkCodeRepo{db: db}
}

func (r *MagicLinkCodeRepo) Create(ctx context.Context, c *MagicLinkCode) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO magic_link_codes (id, code_hash, session_id, organization_id, redirect_origin, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, c.ID, c.CodeHash, c.SessionID, c.OrganizationID, c.RedirectOrigin, c.CreatedAt, c.ExpiresAt)
	return err
}

// Consume atomically marks a live, unconsumed code as used and returns it. It
// returns nil, nil when no row matched. The caller checks the origin after the
// fact, so a wrong origin still burns the code.
func (r *MagicLinkCodeRepo) Consume(ctx context.Context, codeHash string) (*MagicLinkCode, error) {
	var c MagicLinkCode
	err := r.db.QueryRow(ctx, `
		UPDATE magic_link_codes SET consumed_at = NOW()
		WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING id, code_hash, session_id, organization_id, redirect_origin, created_at, expires_at
	`, codeHash).Scan(&c.ID, &c.CodeHash, &c.SessionID, &c.OrganizationID, &c.RedirectOrigin, &c.CreatedAt, &c.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}

// DeleteExpired removes codes that expired before the given time.
func (r *MagicLinkCodeRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.Exec(ctx, `DELETE FROM magic_link_codes WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
