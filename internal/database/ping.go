package database

import "context"

// Ping checks database connectivity.
func (db *AuthDB) Ping(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}

// Ping checks database connectivity.
func (db *IdPDB) Ping(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}
