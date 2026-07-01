package auth

import (
	"context"

	"github.com/auth-project/goauth/internal/database"
	"github.com/auth-project/goauth/internal/domain/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FactorRepo manages MFA factors.
type FactorRepo struct {
	db *database.AuthDB
}

func NewFactorRepo(db *database.AuthDB) *FactorRepo {
	return &FactorRepo{db: db}
}

func (r *FactorRepo) Create(ctx context.Context, f *auth.Factor) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO factors (id, user_id, factor_type, secret_enc, verified, label, credential_id, public_key, sign_count, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, f.ID, f.UserID, f.FactorType, f.SecretEnc, f.Verified, f.Label, f.CredentialID, f.PublicKey, f.SignCount, f.CreatedAt)
	return err
}

func (r *FactorRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]auth.Factor, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, factor_type, COALESCE(label, ''), verified, created_at
		FROM factors WHERE user_id = $1 ORDER BY created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.Factor
	for rows.Next() {
		var f auth.Factor
		if err := rows.Scan(&f.ID, &f.UserID, &f.FactorType, &f.Label, &f.Verified, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *FactorRepo) GetByID(ctx context.Context, id uuid.UUID) (*auth.Factor, error) {
	var f auth.Factor
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, factor_type, COALESCE(secret_enc, ''), verified, COALESCE(label, ''), COALESCE(credential_id, ''), COALESCE(public_key, ''), sign_count, created_at
		FROM factors WHERE id = $1
	`, id).Scan(&f.ID, &f.UserID, &f.FactorType, &f.SecretEnc, &f.Verified, &f.Label, &f.CredentialID, &f.PublicKey, &f.SignCount, &f.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}

func (r *FactorRepo) Delete(ctx context.Context, id, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM factors WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

func (r *FactorRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE factors SET verified = true WHERE id = $1`, id)
	return err
}

func (r *FactorRepo) CreateRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)
	`, uuid.New(), userID, codeHash)
	return err
}

func (r *FactorRepo) UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	res, err := r.db.Exec(ctx, `
		UPDATE mfa_recovery_codes SET used = true WHERE user_id = $1 AND code_hash = $2 AND used = false
	`, userID, codeHash)
	if err != nil {
		return false, err
	}
	return res.RowsAffected() > 0, nil
}

func (r *FactorRepo) DeleteRecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID)
	return err
}
