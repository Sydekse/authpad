package idp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Sydekse/authpad/internal/database"
	"github.com/Sydekse/authpad/internal/domain/idp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrInvitationNotPending = errors.New("invitation is not pending")

type InvitationRepo struct {
	db *database.IdPDB
}

func NewInvitationRepo(db *database.IdPDB) *InvitationRepo {
	return &InvitationRepo{db: db}
}

func (r *InvitationRepo) Create(ctx context.Context, inv *idp.Invitation) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO invitations (id, email, role, payload, token_hash, expires_at, invited_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, inv.ID, inv.Email, inv.Role, inv.Payload, inv.TokenHash, inv.ExpiresAt, inv.InvitedBy, inv.CreatedAt)
	return err
}

func (r *InvitationRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*idp.Invitation, error) {
	return r.scanOne(ctx, `
		SELECT id, email, COALESCE(role, ''), COALESCE(payload, '{}'), token_hash, expires_at, invited_by, redeemed_at, redeemed_user_id, revoked_at, created_at
		FROM invitations WHERE token_hash = $1
	`, tokenHash)
}

func (r *InvitationRepo) GetByID(ctx context.Context, id uuid.UUID) (*idp.Invitation, error) {
	return r.scanOne(ctx, `
		SELECT id, email, COALESCE(role, ''), COALESCE(payload, '{}'), token_hash, expires_at, invited_by, redeemed_at, redeemed_user_id, revoked_at, created_at
		FROM invitations WHERE id = $1
	`, id)
}

func (r *InvitationRepo) List(ctx context.Context, limit int) ([]idp.Invitation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, email, COALESCE(role, ''), COALESCE(payload, '{}'), token_hash, expires_at, invited_by, redeemed_at, redeemed_user_id, revoked_at, created_at
		FROM invitations ORDER BY created_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []idp.Invitation
	for rows.Next() {
		inv, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

func (r *InvitationRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE invitations SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL AND redeemed_at IS NULL`, id)
	return err
}

func (r *InvitationRepo) MarkRedeemed(ctx context.Context, id, userID uuid.UUID) error {
	res, err := r.db.Exec(ctx, `
		UPDATE invitations SET redeemed_at = NOW(), redeemed_user_id = $2
		WHERE id = $1 AND revoked_at IS NULL AND redeemed_at IS NULL
	`, id, userID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvitationNotPending
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (r *InvitationRepo) scanOne(ctx context.Context, q string, arg any) (*idp.Invitation, error) {
	row := r.db.QueryRow(ctx, q, arg)
	inv, err := scanInvitation(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return inv, nil
}

func scanInvitation(row rowScanner) (*idp.Invitation, error) {
	var inv idp.Invitation
	var payload []byte
	err := row.Scan(&inv.ID, &inv.Email, &inv.Role, &payload, &inv.TokenHash, &inv.ExpiresAt, &inv.InvitedBy, &inv.RedeemedAt, &inv.RedeemedUserID, &inv.RevokedAt, &inv.CreatedAt)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	inv.Payload = json.RawMessage(payload)
	return &inv, nil
}
