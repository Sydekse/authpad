# Getting Started

authpad is an embeddable Go authentication library (better-auth-style) with optional internal IdP (profiles, roles, groups).

## Install

```bash
go get github.com/auth-project/authpad
```

## Quick start

1. Set environment variables (see `.env.example` pattern in `cmd/example`).
2. Run migrations:

```bash
go run ./cmd/migrate
```

3. Embed in your chi server:

```go
cfg := auth.LoadFromEnv()
a, err := auth.New(cfg)
if err != nil { log.Fatal(err) }
defer a.Close()

r := chi.NewRouter()
a.Mount(r, "/api/v1")
http.ListenAndServe(":8080", r)
```

Or run the reference server:

```bash
go run ./cmd/example
```

## Required configuration

| Field | Description |
|-------|-------------|
| `AUTH_DATABASE_URL` | PostgreSQL URL for auth tables |
| `IDP_DATABASE_URL` | PostgreSQL URL for profile/roles (optional but recommended) |
| `SESSION_SECRET` | Required in production (32+ chars) |

## Developer-defined roles

Set `ROLES=admin,member,support` or pass `Roles` in code:

```go
cfg.Roles = []auth.RoleDefinition{
    {Name: "admin", Description: "Administrator"},
    {Name: "member", Description: "Default user"},
}
```

Roles are seeded at startup (no hardcoded SQL seeds).

## Custom profile schema

```go
cfg.ProfileSchema = auth.ProfileSchema{
    Fields: []auth.ProfileField{
        {Name: "phone", Type: auth.FieldTypeString, Required: false},
        {Name: "company", Type: auth.FieldTypeString, Required: true},
    },
}
```

Signup body:

```json
{
  "email": "user@example.com",
  "password": "secure-password",
  "profile": {
    "name": "Jane Doe",
    "phone": "+15551234567",
    "company": "Acme"
  }
}
```

Custom fields are stored in `users_profile.metadata` JSONB and validated at runtime.
