package auth

import (
	"context"

	"github.com/auth-project/goauth/internal/database"
	"github.com/auth-project/goauth/internal/domain/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UserAuthRepo handles users_auth table in Auth DB.
type UserAuthRepo struct {
	db *database.AuthDB
}

// NewUserAuthRepo returns a new UserAuthRepo.
func NewUserAuthRepo(db *database.AuthDB) *UserAuthRepo {
	return &UserAuthRepo{db: db}
}

// Create inserts a user into users_auth.
func (r *UserAuthRepo) Create(ctx context.Context, u *auth.UserAuth) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO users_auth (id, email, email_verified, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, u.ID, u.Email, u.EmailVerified, u.Status, u.CreatedAt, u.UpdatedAt)
	return err
}

// GetByID returns a user by ID.
func (r *UserAuthRepo) GetByID(ctx context.Context, id uuid.UUID) (*auth.UserAuth, error) {
	var u auth.UserAuth
	err := r.db.QueryRow(ctx, `
		SELECT id, email, email_verified, status, created_at, updated_at, deleted_at
		FROM users_auth WHERE id = $1 AND deleted_at IS NULL
	`, id).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// GetByEmail returns a user by email.
func (r *UserAuthRepo) GetByEmail(ctx context.Context, email string) (*auth.UserAuth, error) {
	var u auth.UserAuth
	err := r.db.QueryRow(ctx, `
		SELECT id, email, email_verified, status, created_at, updated_at, deleted_at
		FROM users_auth WHERE email = $1 AND deleted_at IS NULL
	`, email).Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// UpdateStatus updates user status (e.g. pending_deletion).
func (r *UserAuthRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string, deletedAt interface{}) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users_auth SET status = $1, updated_at = NOW(), deleted_at = $2 WHERE id = $3
	`, status, deletedAt, id)
	return err
}

// SetEmailVerified marks a user's email as verified.
func (r *UserAuthRepo) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE users_auth SET email_verified = true, updated_at = NOW() WHERE id = $1`, id)
	return err
}

// Anonymize soft-deletes and anonymizes a user record.
func (r *UserAuthRepo) Anonymize(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users_auth SET email = $1, status = 'deleted', deleted_at = NOW(), updated_at = NOW()
		WHERE id = $2
	`, "deleted+"+id.String()+"@anonymous.local", id)
	return err
}

// Delete removes a user row (used for signup rollback).
func (r *UserAuthRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM users_auth WHERE id = $1`, id)
	return err
}
