package auth

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/auth-project/authpad/internal/server"
	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/auth/*.sql
var authMigrations embed.FS

//go:embed migrations/idp/*.sql
var idpMigrations embed.FS

// Auth is the public library instance.
type Auth struct {
	srv *server.Server
}

// New creates and initializes the auth library.
func New(cfg Config) (*Auth, error) {
	if err := ValidateConfig(&cfg); err != nil {
		return nil, err
	}
	srv, err := server.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Auth{srv: srv}, nil
}

// Close releases database connections.
func (a *Auth) Close() {
	if a.srv != nil {
		a.srv.Close()
	}
}

// Mount registers auth routes on a chi router.
func (a *Auth) Mount(r chi.Router, basePath string) {
	a.srv.Mount(r, basePath)
}

// Ready checks database connectivity.
func (a *Auth) Ready(ctx context.Context) error {
	return a.srv.Ready(ctx)
}

// Migrate runs embedded SQL migrations.
func Migrate(ctx context.Context, authURL, idpURL string) error {
	if authURL != "" {
		sub, err := fs.Sub(authMigrations, "migrations/auth")
		if err != nil {
			return err
		}
		if err := runMigrations(authURL, sub); err != nil {
			return fmt.Errorf("auth migrations: %w", err)
		}
		log.Info().Msg("auth database migrations applied")
	}
	if idpURL != "" {
		sub, err := fs.Sub(idpMigrations, "migrations/idp")
		if err != nil {
			return err
		}
		if err := runMigrations(idpURL, sub); err != nil {
			return fmt.Errorf("idp migrations: %w", err)
		}
		log.Info().Msg("idp database migrations applied")
	}
	return nil
}

func runMigrations(dbURL string, migrationFS fs.FS) error {
	source, err := iofs.New(migrationFS, ".")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, dbURL)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}

// MigrateAuth runs auth database migrations only.
func MigrateAuth(ctx context.Context, authURL string) error {
	return Migrate(ctx, authURL, "")
}

// MigrateIdP runs IdP database migrations only.
func MigrateIdP(ctx context.Context, idpURL string) error {
	return Migrate(ctx, "", idpURL)
}
