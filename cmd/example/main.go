package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/auth-project/authpad/internal/handler"
	"github.com/auth-project/authpad/internal/middleware"
	"github.com/auth-project/authpad/pkg/auth"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	_ = godotenv.Load()

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrate()
		return
	}

	cfg := auth.LoadFromEnv()
	if err := auth.ValidateConfig(&cfg); err != nil {
		log.Fatal().Err(err).Msg("config validation failed")
	}

	a, err := auth.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize auth library")
	}
	defer a.Close()

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recovery)
	r.Use(middleware.CORS(cfg.AllowedOrigins))

	r.Get("/api/v1/health", handler.Health)
	r.Get("/api/v1/health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Ready(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not ready"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	a.Mount(r, "/api/v1")

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info().Str("port", cfg.Port).Msg("authpad example server listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func runMigrate() {
	cfg := auth.LoadFromEnv()
	ctx := context.Background()
	if err := auth.Migrate(ctx, cfg.AuthDatabaseURL, cfg.IdPDatabaseURL); err != nil {
		log.Fatal().Err(err).Msg("migration failed")
	}
	log.Info().Msg("migrations complete")
}
