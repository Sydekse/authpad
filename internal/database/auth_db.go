package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthDB wraps the PostgreSQL connection pool for the Auth database.
type AuthDB struct {
	*pgxpool.Pool
}

// NewAuthDB creates a connection pool for the Auth database.
func NewAuthDB(ctx context.Context, connString string) (*AuthDB, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return &AuthDB{Pool: pool}, nil
}
