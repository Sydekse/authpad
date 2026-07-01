package auth

import (
	"context"
	"time"

	"github.com/auth-project/goauth/internal/database"
	"github.com/auth-project/goauth/internal/domain/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionRepo handles sessions table in Auth DB.
type SessionRepo struct {
	db *database.AuthDB
}

// NewSessionRepo returns a new SessionRepo.
func NewSessionRepo(db *database.AuthDB) *SessionRepo {
	return &SessionRepo{db: db}
}

// Create inserts a session.
func (r *SessionRepo) Create(ctx context.Context, s *auth.Session) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, created_at, expires_at, last_active_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, s.ID, s.UserID, s.TokenHash, s.IPAddress, s.UserAgent, s.CreatedAt, s.ExpiresAt, s.LastActiveAt, s.Revoked)
	return err
}

// GetByTokenHash returns a session by token hash if not revoked and not expired.
func (r *SessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*auth.Session, error) {
	var s auth.Session
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, token_hash, COALESCE(ip_address::text, ''), COALESCE(user_agent, ''), created_at, expires_at, last_active_at, revoked
		FROM sessions WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()
	`, tokenHash).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent, &s.CreatedAt, &s.ExpiresAt, &s.LastActiveAt, &s.Revoked)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// UpdateLastActive updates last_active_at for a session.
func (r *SessionRepo) UpdateLastActive(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE sessions SET last_active_at = $1 WHERE id = $2`, time.Now(), id)
	return err
}

// RevokeByID marks a session as revoked.
func (r *SessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE sessions SET revoked = true WHERE id = $1`, id)
	return err
}

// RevokeAllForUser revokes all sessions for a user.
func (r *SessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	res, err := r.db.Exec(ctx, `UPDATE sessions SET revoked = true WHERE user_id = $1`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// ListByUserID returns active sessions for a user.
func (r *SessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]auth.Session, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, token_hash, COALESCE(ip_address::text, ''), COALESCE(user_agent, ''), created_at, expires_at, last_active_at, revoked
		FROM sessions WHERE user_id = $1 AND revoked = false AND expires_at > NOW() ORDER BY last_active_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.Session
	for rows.Next() {
		var s auth.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent, &s.CreatedAt, &s.ExpiresAt, &s.LastActiveAt, &s.Revoked); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// RotateToken updates session token hash and expiry.
func (r *SessionRepo) RotateToken(ctx context.Context, id uuid.UUID, tokenHash string, expiresAt time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions SET token_hash = $1, expires_at = $2, last_active_at = NOW() WHERE id = $3 AND revoked = false
	`, tokenHash, expiresAt, id)
	return err
}
