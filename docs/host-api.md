# Host API

When you wrap Authpad (your Go service mounts the library and adds product routes), use the host API instead of reaching into internals.

## Typical wrappers

```go
cfg := auth.LoadFromEnv()
a, err := auth.New(cfg)
if err != nil { log.Fatal(err) }
defer a.Close()

r := chi.NewRouter()
r.Use(auth.CORS(cfg.AllowedOrigins))

// Your routes first, then mount Authpad.
r.Post("/api/v1/auth/signup", mySignup)
a.Mount(r, "/api/v1")
```

Prefer these helpers:

| Helper | Use |
|--------|-----|
| `IdentityFromRequest` / `RequireUser` | Resolve the caller from cookie or Bearer |
| `CreateAccount` | Create users from a custom signup path |
| `AssignRole` | Attach a **global** role after signup |
| `SetSessionCookie` | Issue the session cookie yourself when needed |
| `CSRF` | CSRF middleware / token helpers |
| `HashToken` | Hash invite or verification tokens the same way Authpad does |
| `EnsureOrganization` | Idempotent seed of a named org (for example a platform company) |
| `CreateOrganization` / `ListOrganizations` / `ListOrgMembers` | Create or list orgs; list members of a slug |
| `SwitchActiveOrganization` / `ClearActiveOrganization` | Bind the session to an org |
| `CreateOrgRole` / `ListOrgRoles` | Per-org role catalog (beyond seeded owner/admin/member) |
| `CreateDepartment` / `CreateLevel` (and list) | Per-org structure |
| `InviteToOrganization` / `AcceptOrganizationInvite` / `PeekOrganizationInvite` | Org invites with optional JSON payload |
| `RequireOrgMember` / `RequireOrgRole` | Authorize company-scoped routes |
| `AddOrganizationMember` / `SetOrganizationRole` | Seed or change a membership without an actor check |
| `UpdateOrgMemberRole` / `RemoveOrgMember` | Owner/admin changes or removes a member, with last-owner protection |
| `LockAccount` / `UnlockAccount` | Lock an account (revokes sessions) or unlock one that is `locked` |
| `PlatformInvite` | Invite into an org when the actor is not a member (platform operator) |
| `SetUserStatus` / `RevokeAllSessions` | Suspend or reactivate an account and drop its sessions |
| `Login` / `CompleteMFA` / `EnrollTOTP` / `ConfirmTOTP` | Password session, TOTP challenge, authenticator enroll, mark a factor verified |
| `ImportAccount` | Insert a user that already has a bcrypt or argon2id hash |

## Overlapping routes

If your host already implements a path Authpad would mount (for example `/admin/roles`), list it in `SkipHTTPPaths` instead of depending on chi match order:

```go
cfg.SkipHTTPPaths = []string{"/admin/roles"}
```

## Public signup off

Hosts that own signup should set `DisablePublicSignup = true` and call `CreateAccount` / `AssignRole` from their handler. Optional `CreateOrganization` + `SwitchActiveOrganization` if the form includes a company. See [getting-started.md](getting-started.md) and [tenancy.md](tenancy.md).

```go
org, err := a.CreateOrganization(ctx, userID, companyName, "", nil)
if err != nil { /* … */ }
_ = a.SwitchActiveOrganization(ctx, sessionID, userID, org.ID)
```

## What not to do

Do not copy session cookie logic, password hashing, or OAuth callback internals out of the library. If a helper is missing, extend the host API in Authpad rather than forking those paths in every product.
