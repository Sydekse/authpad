package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IdPDB wraps the PostgreSQL connection pool for the IdP database.
type IdPDB struct {
	*pgxpool.Pool
}

// NewIdPDB creates a connection pool for the IdP database.
func NewIdPDB(ctx context.Context, connString string) (*IdPDB, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return &IdPDB{Pool: pool}, nil
}
