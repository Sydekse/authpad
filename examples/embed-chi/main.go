package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/Sydekse/authpad/pkg/auth"
	"github.com/go-chi/chi/v5"
)

func main() {
	cfg := auth.LoadFromEnv()
	if cfg.AuthDatabaseURL == "" {
		log.Fatal("AUTH_DATABASE_URL is required")
	}
	if err := auth.Migrate(context.Background(), cfg.AuthDatabaseURL, cfg.IdPDatabaseURL); err != nil {
		log.Fatal(err)
	}
	a, err := auth.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	r.Use(auth.CORS(cfg.AllowedOrigins))
	a.Mount(r, "/api/v1")
	addr := ":" + cfg.Port
	if cfg.Port == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		os.Exit(1)
	}
}
