# Schema

## Base profile fields

Always available on signup/update:

| Field | Storage | Required |
|-------|---------|----------|
| `name` | `users_profile.name` | Yes |
| `image_url` | `users_profile.image_url` | No |
| `bio` | `users_profile.bio` | No |

## Custom fields

Declare additional fields in `ProfileSchema.Fields`. Values are stored in `users_profile.metadata` as JSONB.

Supported types: `string`, `email`, `url`, `int`, `bool`, `json`.

Optional per-field `Validate func(any) error` for custom rules.

## Validation

Validation runs in the service layer before writes. Signup rejects unknown fields and missing required custom fields.

## Example

```go
cfg.ProfileSchema = auth.ProfileSchema{
    Fields: []auth.ProfileField{
        {
            Name:     "referral_code",
            Type:     auth.FieldTypeString,
            Required: false,
            Unique:   true,
        },
    },
}
```

## Roles

There are two catalogs:

- **Global** IdP roles (`Config.Roles`, `user_roles`) — assign with `POST /api/v1/account/role` (self-service, allowed names only) or `POST /api/v1/admin/roles/assign` (admin).
- **Organization** roles (`organization_roles` on each org) — seeded `owner` / `admin` / `member`; add more with `POST /organizations/{slug}/roles`. Membership `role` must exist on **that org**.

Do not use a profile metadata field as a substitute for either catalog. See [tenancy.md](tenancy.md).
