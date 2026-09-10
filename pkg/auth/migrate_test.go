package auth_test

import (
	"context"
	"os"
	"testing"

	"github.com/Sydekse/authpad/pkg/auth"
)

// testDSN returns the integration database, skipping locally when it is not
// configured. Under CI a missing DSN is a failure instead, so these tests
// cannot silently stop running.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AUTHPAD_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUTHPAD_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("AUTHPAD_TEST_DATABASE_URL not set")
	}
	return dsn
}

func TestMigrateSameDatabaseTwoLedgers(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	err := auth.MigrateWithOptions(ctx, dsn, dsn, auth.MigrationOptions{
		AuthTable: "schema_migrations_auth",
		IdPTable:  "schema_migrations_idp",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := auth.DefaultConfig()
	cfg.AuthDatabaseURL = dsn
	cfg.IdPDatabaseURL = dsn
	cfg.Security.SessionSecret = "integration-test-session-secret-32chars"
	cfg.OAuth.AllowedRedirects = []string{"https://app.example.com/callback"}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Ready(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectAllowedRejectsUnknown(t *testing.T) {
	cfg := auth.DefaultConfig()
	cfg.OAuth.AllowedRedirects = []string{"https://app.example.com/cb"}
	if auth.RedirectAllowed(&cfg, "https://evil.test/") {
		t.Fatal("expected rejection")
	}
	if !auth.RedirectAllowed(&cfg, "https://app.example.com/cb") {
		t.Fatal("expected allowlist hit")
	}
}
