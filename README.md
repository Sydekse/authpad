# authpad

Embeddable Go authentication library with optional internal IdP (profiles, roles, groups). Inspired by [better-auth](https://www.better-auth.com/) — configure schema, roles, and hosted pages; mount on your existing chi router.

## Features

- Email/password auth, sessions (cookie + Bearer), OAuth (Google/GitHub)
- Developer-defined profile schema (custom fields in JSONB metadata)
- Configurable roles seeded at startup
- Hosted-page redirect model (no bundled UI required)
- Audit logs, email verification, session hardening, MFA (TOTP/WebAuthn), GDPR delete/export
- Embedded migrations via golang-migrate

## Project layout

```
auth-api/
├── pkg/auth/           # Public library API
├── internal/           # Handlers, services, repos
├── cmd/example/        # Reference HTTP server
├── cmd/migrate/        # Migration CLI
├── examples/
│   ├── embed-chi/      # Minimal integration
│   └── nextjs-hosted-pages/  # Reference Next.js UI
└── docs/
```

## Quick start

```bash
cp .env .env.local   # configure AUTH_DATABASE_URL, IDP_DATABASE_URL
go run ./cmd/migrate
go run ./cmd/example
```

## Library usage

```go
import "github.com/auth-project/authpad/pkg/auth"

cfg := auth.DefaultConfig()
cfg.AuthDatabaseURL = os.Getenv("AUTH_DATABASE_URL")
cfg.IdPDatabaseURL = os.Getenv("IDP_DATABASE_URL")
cfg.Roles = []auth.RoleDefinition{{Name: "admin"}, {Name: "member"}}
cfg.Pages.SignInURL = "https://app.example.com/signin"

a, _ := auth.New(cfg)
defer a.Close()
a.Mount(router, "/api/v1")
```

See [docs/getting-started.md](docs/getting-started.md) for full documentation.

## Architecture

- **Auth DB** — credentials, sessions, OAuth, MFA, audit
- **IdP DB** (optional) — profiles, roles, groups

Account operations coordinate across both databases with compensating rollback on failure.

## License

MIT
