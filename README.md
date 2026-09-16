# authpad

Embeddable Go authentication library with optional IdP (profiles, roles, groups) and an opt-in company tenancy module.

**Full docs:** [https://docs.sydek.dev/docs/authpad](https://docs.sydek.dev/docs/authpad) (local: `http://localhost:3005/docs/authpad`).

This is the public starter pack for running your own Go auth service. Sydek’s hosted login app (`auth.sydek.dev`) is a separate internal product.

## Features

- Email/password auth, opaque sessions (cookie + Bearer), OAuth (Google/GitHub)
- Developer-defined profile schema and seeded roles
- Hosted-page redirect model (no bundled UI)
- Audit logs, email verification, CSRF, rate limits, TOTP MFA
- Optional invitations and workspace-style organizations
- Embedded PostgreSQL migrations

## Install

```bash
go get github.com/Sydekse/authpad
```

## Quick start

```go
import "github.com/Sydekse/authpad/pkg/auth"

cfg := auth.LoadFromEnv()
cfg.OAuth.AllowedRedirects = []string{"https://app.example.com/callback"}
if err := auth.Migrate(ctx, cfg.AuthDatabaseURL, cfg.IdPDatabaseURL); err != nil {
    log.Fatal(err)
}
a, err := auth.New(cfg)
if err != nil { log.Fatal(err) }
defer a.Close()

r := chi.NewRouter()
r.Use(auth.CORS(cfg.AllowedOrigins))
a.Mount(r, "/api/v1")
```

Same-database auth + IdP ledgers:

```go
err := auth.MigrateWithOptions(ctx, dsn, dsn, auth.MigrationOptions{
    AuthTable: "schema_migrations_auth",
    IdPTable:  "schema_migrations_idp",
})
```

## Company tenancy

Off by default. Enable with `AUTHPAD_TENANCY_ENABLED=true` or `cfg.Tenancy.Enabled = true` (requires IdP). Users can belong to many organizations, switch `active_organization_id` on the session, and hold **per-org** roles (seeded `owner`, `admin`, `member`; hosts may add more). Each organization also has its own departments and levels. Set `MaxMembershipsPerUser: 1` for single-home products. Hosts can seed an org with `EnsureOrganization`.

## Invitations

Enable with `AUTHPAD_INVITATIONS_ENABLED=true`. Hosts that already implement invites (for example Sydek auth-service) should leave this off.

## Host API

Wrappers should use `IdentityFromRequest`, `CreateAccount`, `AssignRole`, `SetSessionCookie`, `CSRF`, and `HashToken` instead of copying internals. Overlapping host routes should be listed in `SkipHTTPPaths`.

See [docs/getting-started.md](docs/getting-started.md).

## License

MIT
