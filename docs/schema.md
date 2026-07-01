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

Roles are not part of the profile schema. Define them via `Config.Roles` and assign with:

- `POST /api/v1/account/role` (self-service, allowed roles only)
- `POST /api/v1/admin/roles/assign` (admin only)
