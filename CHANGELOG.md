# Changelog

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
