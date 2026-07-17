# Compliance

## OWASP hardening

- Argon2id password hashing with optional pepper (`PEPPER_KEY`)
- Configurable password policy (`PASSWORD_MIN_LENGTH`, etc.)
- Rate limiting per IP (`RATE_LIMIT_RPM`, `RATE_LIMIT_BURST`)
- Redis-backed rate limiting when `REDIS_URL` is set
- CSRF protection on state-changing cookie-auth endpoints
- Secure session cookies (`COOKIE_SECURE`, `COOKIE_DOMAIN`)

## Audit logging

Security events are written to `auth_audit_logs` and `idp_audit_logs`:

- Login, logout, failed auth
- Password reset, email verification
- MFA enroll/remove
- Profile updates, role changes
- Account delete/export

Endpoints:

- `GET /api/v1/account/audit` — current user's logs
- `GET /api/v1/admin/audit` — admin-only recent logs

## Email verification

Enable with `REQUIRE_EMAIL_VERIFICATION=true`. Unverified users cannot log in when enabled.

## Session hardening

Configure via env or `SessionConfig`:

- `SESSION_TTL` — default session lifetime
- `SESSION_IDLE_TIMEOUT` — revoke after inactivity
- `SESSION_MAX_LIFETIME` — absolute cap
- Session rotation on interval (when configured)

Device management:

- `GET /api/v1/account/sessions`
- `DELETE /api/v1/account/sessions/{id}`
- `POST /api/v1/auth/logout-all`

## MFA

- List factors: `GET /api/v1/auth/mfa`
- TOTP: `POST /api/v1/auth/mfa/enroll`, `POST /api/v1/auth/mfa/verify`
- WebAuthn (simplified): register begin/finish endpoints
- Recovery codes generated on TOTP enroll
- Remove factor: `DELETE /api/v1/auth/mfa/{id}`

## GDPR

- `DELETE /api/v1/account` — anonymizes auth user, clears profile, revokes sessions
- `GET /api/v1/account/export` — JSON export of account, profile, roles, sessions, audit logs

## Service-to-service auth

Set `SERVICE_KEY` and pass `X-Service-Key` header to access IdP user endpoints and admin APIs without a user session.

## IdP authorization

`GET /api/v1/idp/users/{id}` requires: same user, admin role, or valid service key.
