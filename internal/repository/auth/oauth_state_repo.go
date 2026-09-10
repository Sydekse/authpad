package auth

import (
	"context"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/database"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
)

type OAuthStateRepo struct {
	db *database.AuthDB
}

func NewOAuthStateRepo(db *database.AuthDB) *OAuthStateRepo {
	return &OAuthStateRepo{db: db}
}

func (r *OAuthStateRepo) Create(ctx context.Context, redirectURI string, ttl time.Duration) (state string, err error) {
	state, err = security.GenerateOpaqueToken()
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO oauth_states (id, state_hash, redirect_uri, expires_at)
		VALUES ($1, $2, $3, $4)
	`, uuid.New(), security.HashToken(state), redirectURI, time.Now().Add(ttl))
	if err != nil {
		return "", err
	}
	return state, nil
}

// Consume deletes the state row and returns the stored redirect URI. One-time use.
func (r *OAuthStateRepo) Consume(ctx context.Context, state string) (redirectURI string, ok bool) {
	state = strings.TrimSpace(state)
	if state == "" {
		return "", false
	}
	var uri string
	err := r.db.QueryRow(ctx, `
		DELETE FROM oauth_states
		WHERE state_hash = $1 AND expires_at > NOW()
		RETURNING redirect_uri
	`, security.HashToken(state)).Scan(&uri)
	if err != nil {
		return "", false
	}
	return uri, true
}
