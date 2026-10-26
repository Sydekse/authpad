# Changelog

## Unreleased

- `POST /auth/password` (session + CSRF, rate limited) sets a password for a signed-in, email-verified account that has none (magic-link or OAuth sign-ups) when the session is under 30 minutes old, or changes it when `current_password` matches. Every other session of the user is revoked; no email is sent. Errors: `WEAK_PASSWORD`, `INVALID_CURRENT_PASSWORD`, `REAUTH_REQUIRED`, `EMAIL_NOT_VERIFIED`, `ACCOUNT_INACTIVE`. Audited as `password.set`, `password.change` and `password.change.failed` (with a reason).
- `GET /account` reports `has_password`.
- Branded transactional emails. Invites, magic links, password reset and verification share one light, table-based layout with a coloured header band, optional logo, rounded button, plain-text alternative and dark-mode support. Configure with `EMAIL_HEADER_COLOR`, `EMAIL_BUTTON_COLOR`, `EMAIL_LOGO_URL`, `EMAIL_LOGO_WIDTH`, `EMAIL_FONT_FAMILY`, `EMAIL_HEADING_FONT_FAMILY`, `EMAIL_FOOTER_TEXT` and `EMAIL_ORG_INVITE_TITLE` / `_BODY` / `_BUTTON` (`Config.Email.Brand`). See docs/emails.md. The "Identity" label, "© Sydek" footer and role names ("as admin") are gone from emails.
- Organization invites name the organization. New optional `OrgInvitationMailer` interface; existing `Mailer` implementations are unaffected.
- Invite, reset and verification links percent-encode the token, and `GET /invitations/{token}/validate` and `GET /organizations/invitations/{token}/validate` accept a percent-encoded token. Before, a token whose `=` padding was sent as `%3D` never matched.
- Failed invite emails are logged (without the link) instead of being dropped silently.
- **Behaviour change:** an invite `callback_url` must be on an allowed origin (`AUTHPAD_INVITE_CALLBACK_ORIGINS`, falling back to `ALLOWED_ORIGINS`, `MAGIC_LINK_REDIRECT_ALLOWLIST` and the hosted page origins). Other URLs, and non-http(s) schemes, now return `400 INVALID_CALLBACK_URL`.
- Email copy quotes the real link lifetimes (`PasswordResetTTL`, `EmailVerificationTTL`, `MAGIC_LINK_TTL`, the invite TTL).

- Passwordless magic-link sign-in: `POST /magic-link` (always 202) and `GET /magic-link/verify`. Opt in with `MAGIC_LINK_ENABLED=true`; requires tenancy. Tokens are 32 random bytes, stored as SHA-256 only, valid 15 minutes, single use. Per-email and per-IP limits, Resend delivery (dev: link printed to stdout), exact-origin redirect allowlist. Does not create org membership. See docs/magic-link.md.
- Migration `000007_magic_link_tokens` (Auth DB). New config: `Config.MagicLink`, `MagicLinkMailer`.
- Magic-link one-time-code flow for apps on another registrable domain: `MAGIC_LINK_CODE_FLOW=true` makes verify redirect with `?code=` instead of setting a cookie, and `POST /magic-link/exchange` (header `X-Authpad-Exchange-Secret` = `MAGIC_LINK_EXCHANGE_SECRET`, per-IP limit `MAGIC_LINK_EXCHANGE_LIMIT`) redeems it server-to-server for a session bearer token. Codes are 32 random bytes, stored as SHA-256 only, valid 60 seconds, single use, bound to session, tenant and redirect origin. Migration `000008_magic_link_codes` (Auth DB). New config: `MagicLink.CodeFlow`, `ExchangeSecret`, `ExchangeLimit`.

- Magic-link security review fixes:
  - Account takeover: verifying a previously unverified account revokes all its sessions, deletes its password credential and clears its MFA factors and recovery codes. A verified account with no password may now set one through the password reset flow.
  - Magic link is refused (generic failure) for staff/admin accounts, and for accounts with a password unless `MAGIC_LINK_ALLOW_PASSWORD_ACCOUNTS=true`. New config: `MagicLink.AllowPasswordAccounts`.
  - `/magic-link/exchange` returns `org_id` and `role` only for active members, plus `is_member`; `org_id` is `null` for non-members.
  - PKCE for the code flow: `POST /magic-link` requires `code_challenge` (S256) and `/magic-link/exchange` requires `code_verifier`. Migration `000009_magic_link_pkce` adds `code_challenge` to tokens and codes.
  - `GET /magic-link/verify` now renders a confirmation page and no longer consumes the token; `POST /magic-link/verify` does. The link in the email is unchanged. Hosts that called the GET URL directly must now post the form.
  - The code flow refuses to start without `MAGIC_LINK_DEFAULT_REDIRECT` or `CALLBACK_URL`, and magic link with any `Env` other than `development` refuses to start without a mail key or custom mailer. The dev mailer is only used when `Env` is `development` and redacts tokens otherwise.
  - Expired magic-link tokens and codes are purged hourly by a background job.
  - `X-Forwarded-For` is now ignored unless `TRUSTED_PROXY_CIDRS` (`Security.TrustedProxyCIDRs`) is set and the connection comes from inside it; then the right-most untrusted hop is the client. **Deployments behind a reverse proxy must set it**, or all clients share the proxy's address for rate limits and audit. This applies to every endpoint, not only magic link. `middleware.RateLimiter` takes a new `trusted []*net.IPNet` argument.
  - Known limitations (per-tenant redirects, shared exchange secret, Redis limiter, in-flight cap) are documented in docs/magic-link.md.

## 0.3.0

- Account lock: `POST /admin/users/{id}/lock` and `/unlock`. Locked password and OAuth sign-in return `ACCOUNT_LOCKED`. Unlock only clears `locked`, not `suspended`.
- Organization owners and admins can change or remove an existing member’s role (`PATCH` / `DELETE /organizations/{slug}/members/{userId}`). The last owner cannot be removed. Admins cannot change owners or admins, or assign `admin`.
- `SESSION_STAFF_IDLE_TIMEOUT` and `Tenancy.StaffOrgRoles`. Staff sessions idle out on that window, including remember-me. Zero leaves the normal idle timeout.
- Password verify accepts imported bcrypt hashes (`$2a$`, `$2b$`, `$2y$`).
- Host helpers for login, MFA, account import, status, and session revoke (`LockAccount`, `UnlockAccount`, `Login`, `ImportAccount`, and related calls).

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
