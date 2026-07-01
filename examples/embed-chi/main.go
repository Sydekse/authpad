package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/auth-project/goauth/internal/middleware"
	"github.com/auth-project/goauth/pkg/auth"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Minimal embed example — mount goauth on your existing chi router.
func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	_ = godotenv.Load()

	cfg := auth.DefaultConfig()
	cfg.AuthDatabaseURL = os.Getenv("AUTH_DATABASE_URL")
	cfg.IdPDatabaseURL = os.Getenv("IDP_DATABASE_URL")
	cfg.Security.SessionSecret = os.Getenv("SESSION_SECRET")
	cfg.AllowedOrigins = []string{"http://localhost:3000"}

	a, err := auth.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("auth init failed")
	}
	defer a.Close()

	r := chi.NewRouter()
	r.Use(middleware.CORS(cfg.AllowedOrigins))
	a.Mount(r, "/api/v1")

	srv := &http.Server{Addr: ":8080", Handler: r}
	go func() { _ = srv.ListenAndServe() }()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	_ = srv.Shutdown(contextWithTimeout())
}

func contextWithTimeout() (ctx context.Context) {
	ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)
	return ctx
}
