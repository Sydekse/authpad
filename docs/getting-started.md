# Getting Started

authpad is an embeddable Go authentication library (better-auth-style) with optional internal IdP (profiles, roles, groups).

## Install

```bash
go get github.com/Sydekse/authpad
```

## Quick start

1. Set environment variables (copy [`.env.example`](../.env.example)).
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

## Optional company tenancy

```go
cfg.Tenancy.Enabled = true
cfg.Tenancy.AllowCreateOrganization = true
cfg.Tenancy.AllowPersonalAccounts = true
cfg.Tenancy.MaxMembershipsPerUser = 0 // unlimited; use 1 for single-home
```

Mounted when enabled: `POST/GET /organizations`, org members/invites, `POST /session/organization`.

Company-mode signup (`RequireOnSignup`) must create an organization (`organization_name`) or accept `org_invite_token`. Session and `/account` include `organization` and `org_role` when an org is active.

Hosts that already register overlapping routes should set `cfg.SkipHTTPPaths` (for example `"/admin/roles"`) instead of depending on chi match order.

## Replacing public signup

```go
cfg.DisablePublicSignup = true
r.Post("/api/v1/auth/signup", mySignup)
a.Mount(r, "/api/v1")
```

Use `a.CreateAccount` and `a.AssignRole` in `mySignup`.

