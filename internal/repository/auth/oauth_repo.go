package auth

import (
	"context"

	"github.com/auth-project/goauth/internal/database"
	"github.com/auth-project/goauth/internal/domain/auth"
	"github.com/jackc/pgx/v5"
)

// OAuthAccountRepo handles oauth_accounts table in Auth DB.
type OAuthAccountRepo struct {
	db *database.AuthDB
}

// NewOAuthAccountRepo returns a new OAuthAccountRepo.
func NewOAuthAccountRepo(db *database.AuthDB) *OAuthAccountRepo {
	return &OAuthAccountRepo{db: db}
}

// Create inserts an OAuth account link.
func (r *OAuthAccountRepo) Create(ctx context.Context, o *auth.OAuthAccount) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO oauth_accounts (id, user_id, provider, provider_account_id, access_token_enc, refresh_token_enc, token_expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, o.ID, o.UserID, o.Provider, o.ProviderAccountID, o.AccessTokenEnc, o.RefreshTokenEnc, o.TokenExpiresAt, o.CreatedAt, o.UpdatedAt)
	return err
}

// GetByProviderAndAccountID returns the OAuth account for a provider and provider account ID.
func (r *OAuthAccountRepo) GetByProviderAndAccountID(ctx context.Context, provider, providerAccountID string) (*auth.OAuthAccount, error) {
	var o auth.OAuthAccount
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, provider, provider_account_id, created_at, updated_at
		FROM oauth_accounts WHERE provider = $1 AND provider_account_id = $2
	`, provider, providerAccountID).Scan(&o.ID, &o.UserID, &o.Provider, &o.ProviderAccountID, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &o, nil
}
