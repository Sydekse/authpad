package main

import (
	"context"

	"github.com/auth-project/goauth/pkg/auth"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	_ = godotenv.Load()
	cfg := auth.LoadFromEnv()
	if err := auth.Migrate(context.Background(), cfg.AuthDatabaseURL, cfg.IdPDatabaseURL); err != nil {
		log.Fatal().Err(err).Msg("migration failed")
	}
	log.Info().Msg("migrations complete")
}
