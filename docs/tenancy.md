# Tenancy and invitations

Both features are **off by default**. Enable only what your product needs. Requires an IdP database.

Authpad **v0.2.0** made company structure first-class: each organization has its own roles, departments, and levels. Memberships can point at a department and level. Organization invitations carry a JSON payload.

## Company tenancy

An **account** is a person. An **organization** is a company (or any workspace). One account may belong to zero, one, or many organizations. The session may have an optional `active_organization_id`.

```go
cfg.Tenancy.Enabled = true
cfg.Tenancy.AllowCreateOrganization = true
cfg.Tenancy.AllowPersonalAccounts = true
cfg.Tenancy.RequireOnSignup = false
cfg.Tenancy.MaxMembershipsPerUser = 0 // unlimited; use 1 for single-home
cfg.Tenancy.DefaultOrgRole = "member"
```

Or `AUTHPAD_TENANCY_ENABLED=true`. Related env: `AUTHPAD_TENANCY_PERSONAL` (default on unless `false`), `AUTHPAD_TENANCY_CREATE_ORG` (default on unless `false`), `AUTHPAD_TENANCY_REQUIRE_ON_SIGNUP`, `AUTHPAD_TENANCY_MAX_MEMBERSHIPS`, `AUTHPAD_TENANCY_DEFAULT_ORG_ROLE`.

| Flag | Effect |
|------|--------|
| `AllowPersonalAccounts` | Users may exist with no membership |
| `AllowCreateOrganization` | Authenticated users may `POST /organizations` |
| `RequireOnSignup` | Signup / OAuth must create an org or redeem `org_invite_token` |
| `MaxMembershipsPerUser` | `0` = unlimited |
| `OrgRoles` | **Seed list** for new orgs (default `owner`, `admin`, `member`), not a process-wide allowlist |

`GET /account` includes `organization` and `org_role` when the session has an active org.

## Per-organization catalogs

On create (and on `EnsureOrganization` for a new slug), Authpad seeds `owner`, `admin`, and `member` into `organization_roles`. Hosts add more with `CreateOrgRole` or `POST /organizations/{slug}/roles` (owner-only; you cannot create another `owner`).

Each org also has:

- **Departments** — unique name per org
- **Levels** — unique name per org
- **Membership** — `role` must exist on that org; optional `department_id` / `level_id`

Role checks (`RequireOrgRole`, invite `role`) look up **that org’s catalog**, not `cfg.Roles` (those are global IdP roles).

Changing a member who is already in the org is `PATCH /organizations/{slug}/members/{userId}` with `{ "role": "support" }`. `DELETE` on that path removes them. Hosts can call `UpdateOrgMemberRole` and `RemoveOrgMember` with the acting user id. `SetOrganizationRole` still writes a role with no actor check (bootstrap and repair).

The last active `owner` cannot be demoted or removed. An `admin` can change or remove `member` and other non-admin roles, and cannot assign `admin` or `owner`.

## HTTP (when tenancy is on)

Mounted under your `Mount` prefix (for example `/api/v1`). Callers must be members unless noted.

| Method | Path | Notes |
|--------|------|--------|
| `POST` / `GET` | `/organizations` | Create (actor becomes owner) / list mine |
| `GET` / `PATCH` | `/organizations/{slug}` | Member read; owner/admin patch |
| `GET` | `/organizations/{slug}/members` | Membership-checked |
| `PATCH` | `/organizations/{slug}/members/{userId}` | `{ "role" }`. Owner or admin. Cannot assign `owner`. Admin cannot change an owner or admin, or assign `admin`. |
| `DELETE` | `/organizations/{slug}/members/{userId}` | Ends the membership (`status=removed`). The last owner cannot be removed. |
| `GET` / `POST` | `/organizations/{slug}/roles` | Create is owner-only |
| `GET` / `POST` / `DELETE` | `/organizations/{slug}/departments` | |
| `GET` / `POST` / `DELETE` | `/organizations/{slug}/levels` | |
| `GET` / `POST` | `/organizations/{slug}/invitations` | Cannot invite `owner` |
| `DELETE` | `/organizations/{slug}/invitations/{id}` | |
| `POST` | `/organizations/invitations/accept` | `{ "token" }` for an existing account |
| `GET` | `/organizations/invitations/{token}/validate` | Public; `{ valid, invite }` |
| `POST` | `/session/organization` | `{ "slug" }` or `{ "organization_id" }`; empty body clears |

Invite body:

```json
{
  "email": "teammate@example.com",
  "role": "member",
  "payload": { "department_id": "…", "level_id": "…", "position": "Engineer" },
  "callback_url": "https://app.example.com/invite"
}
```

`role` must exist **on that org**. `payload` is stored as JSON. On accept, `department_id` / `level_id` are applied if they belong to the org. If `callback_url` is set, Authpad emails `callback_url?token=…` through the configured mailer.

## Host API

Wrappers (custom signup, bootstrap, product routes) should not go through HTTP. See [host-api.md](host-api.md).

```go
org, err := a.EnsureOrganization(ctx, "acme", "Acme", ownerID)
_, _ = a.CreateOrgRole(ctx, org.ID, "billing", "Can manage invoices")
_, _ = a.CreateLevel(ctx, org.ID, "manager")
```

## Invite policy hook

`Hooks.OrgInvitePolicy` runs before an org invitation is written. Return an error to deny (for example `auth.ErrOrgForbidden`). Authpad still refuses inviting `owner`; extra hierarchy is the host’s job.

```go
cfg.Hooks.OrgInvitePolicy = func(ctx context.Context, actor uuid.UUID, orgSlug, email, role string) error {
    // Deny or allow. orgSlug is the target organization.
    return nil
}
```

## Generic invitations (separate)

Enable with `AUTHPAD_INVITATIONS_ENABLED=true`.

This is the **generic** user-invite table (`/admin/invitations`), not organization invitations. Hosts that already implement invites, or that use org invites instead, should leave this off.
