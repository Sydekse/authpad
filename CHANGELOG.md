# Changelog

## 0.2.0

- Per-organization roles, departments, and levels
- Organization invitations carry a JSON payload; memberships may reference a department and level
- Host API: EnsureOrganization, org structure CRUD, invite/accept, RequireOrgMember / RequireOrgRole
- Org invite policy hook for host-specific invite hierarchies

## 0.1.1

- Security: service-key checks and CSRF cookie comparison use constant-time equality
- Hosts can replace Resend for password-reset and verification mail, not only invitations
- Redeeming an already-used invitation now fails instead of reporting success
- Removed unused `ValidateConfigProduction` (production page checks live in `Validate`)
- Stopped shipping compiled `server` and `out` binaries in the module zip

## 0.1.0

- Security: CSRF no longer bypasses on an unvalidated Bearer header or empty service key
- Security: OAuth return URLs must pass AllowedRedirects or ValidateReturnURL; state is one-time; session cookies are set without putting tokens in query strings
- Security: login and OAuth challenge MFA when a verified factor exists
- Security: WebAuthn registration returns 501 until attestation is implemented
- Security: signup/login/delete hooks fail the request; self-assign cannot take AdminRoleName
- Host API: IdentityFromRequest, RequireUser, cookies, CSRF, CreateAccount, AssignRole, HashToken, MigrationOptions
- Optional generic invitations (`AUTHPAD_INVITATIONS_ENABLED`)
- Optional workspace-style company tenancy (`AUTHPAD_TENANCY_ENABLED`)
- Hosts can skip overlapping routes with `SkipHTTPPaths`
- Canonical module path `github.com/Sydekse/authpad`
- Every embedded migration ships an accompanying down migration
