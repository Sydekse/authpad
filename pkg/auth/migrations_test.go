package auth

import (
	"embed"
	"io"
	"io/fs"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// The migration files are only exercised against Postgres in CI. This checks
// the cheap half locally: that golang-migrate can parse every filename and
// that each version has both an up and a down.
func TestEmbeddedMigrationsAreComplete(t *testing.T) {
	for _, tc := range []struct {
		name string
		fsys embed.FS
		dir  string
	}{
		{"auth", authMigrations, "migrations/auth"},
		{"idp", idpMigrations, "migrations/idp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := fs.Sub(tc.fsys, tc.dir)
			if err != nil {
				t.Fatal(err)
			}
			driver, err := iofs.New(sub, ".")
			if err != nil {
				t.Fatalf("golang-migrate rejected %s: %v", tc.dir, err)
			}
			defer driver.Close()

			version, err := driver.First()
			if err != nil {
				t.Fatalf("no migrations found in %s: %v", tc.dir, err)
			}
			count := 0
			for {
				count++
				for _, d := range []struct {
					label string
					read  func(uint) (io.ReadCloser, string, error)
				}{
					{"up", driver.ReadUp},
					{"down", driver.ReadDown},
				} {
					body, _, err := d.read(version)
					if err != nil {
						t.Fatalf("%s migration %d has no %s: %v", tc.dir, version, d.label, err)
					}
					body.Close()
				}
				next, err := driver.Next(version)
				if err != nil {
					break
				}
				version = next
			}
			if count == 0 {
				t.Fatalf("%s has no migrations", tc.dir)
			}
		})
	}
}
