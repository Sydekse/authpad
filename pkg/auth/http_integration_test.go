package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Sydekse/authpad/pkg/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func testAuth(t *testing.T) (*auth.Auth, auth.Config) {
	t.Helper()
	dsn := os.Getenv("AUTHPAD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHPAD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := auth.MigrateWithOptions(ctx, dsn, dsn, auth.MigrationOptions{
		AuthTable: "schema_migrations_auth",
		IdPTable:  "schema_migrations_idp",
	}); err != nil {
		t.Fatal(err)
	}
	cfg := auth.DefaultConfig()
	cfg.AuthDatabaseURL = dsn
	cfg.IdPDatabaseURL = dsn
	cfg.Security.CSRFEnabled = true
	cfg.Security.RateLimitRPM = 0
	cfg.Security.SessionSecret = "integration-test-session-secret-32chars"
	cfg.OAuth.AllowedRedirects = []string{"https://app.example.com/callback"}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, cfg
}

func mounted(a *auth.Auth) http.Handler {
	r := chi.NewRouter()
	a.Mount(r, "/api/v1")
	return r
}

func TestLoginRequiresCSRF(t *testing.T) {
	a, _ := testAuth(t)
	h := mounted(a)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"email":"a@b.c","password":"password1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login without CSRF should be 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoginWithCSRF(t *testing.T) {
	a, _ := testAuth(t)
	email := fmt.Sprintf("user-%s@example.com", uuid.NewString())
	_, err := a.CreateAccount(context.Background(), auth.CreateAccountRequest{
		Email:    email,
		Password: "password1",
		Profile:  map[string]any{"name": "Test User"},
	}, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	h := mounted(a)
	body, _ := json.Marshal(map[string]any{"email": email, "password": "password1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	req.Header.Set("X-CSRF-Token", "test-csrf")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login with CSRF should succeed, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOAuthRejectsUnknownRedirect(t *testing.T) {
	a, _ := testAuth(t)
	h := mounted(a)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/google?redirect_uri=https://evil.test/cb", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown OAuth redirect should be 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
