# Magic-link sign-in

Passwordless sign-in for attendees of an organization (tenant). **Off by default.** Requires tenancy (`AUTHPAD_TENANCY_ENABLED=true`) and an IdP database. Apply migration `000007_magic_link_tokens` first.

## Flow

1. `POST /api/v1/magic-link` with `{ "email", "tenant", "redirect_to" }`. `tenant` is an organization slug or id. `redirect_to` is optional.
2. The user receives a link to `GET /api/v1/magic-link/verify?token=…&tenant=<slug>`.
3. Verify consumes the token, finds or creates the account, creates a session exactly like password login, and answers `303`.

### Request

Always `202 {"ok":true}` once the body parses as JSON (malformed JSON is `400`). The response is identical whether the email or tenant exists, whether the request was rate limited, and whether `redirect_to` was acceptable. Work happens after the response is decided (bounded background workers), so timing does not reveal the outcome and a slow mail API never delays it. Delivery errors are logged (never with the token) and do not change the response.

Emails are trimmed and lowercased. Invalid addresses, unknown tenants, and limited requests send nothing.

### Verify

- The token is hashed and consumed in one statement: `UPDATE … SET consumed_at = now() WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING …`. Two concurrent clicks cannot both succeed.
- Optional `tenant` query parameter: if present it must resolve to the organization the token was issued for. A mismatch is rejected **without** consuming the token. (Host-based tenant selection is not implemented.)
- Unknown, expired, reused, wrong-tenant and locked-account cases all give the same answer: a `303` to `Pages.ErrorURL?error=invalid_link` when `ERROR_URL` is set, otherwise `400 INVALID_OR_EXPIRED_TOKEN`.
- Success sets the session cookie and `csrf_token` cookie, writes a `login.success` audit entry (`method: magic_link`), runs `Hooks.OnLogin`, and redirects. If the user has MFA, the session is created MFA-pending and must pass `/auth/mfa/challenge`, as with password login.
- If the user is already an active member of the tenant, it becomes the session's active organization.
- The response carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

### Redirects

`redirect_to` is accepted only if it is an absolute `http(s)` URL whose scheme, host and port **exactly** equal an entry in `MAGIC_LINK_REDIRECT_ALLOWLIST` (comma-separated origins such as `https://app.example.com`; default ports are normalized, entries with a path or userinfo are ignored). Userinfo, backslashes, whitespace/control characters, protocol-relative URLs, relative paths and non-http(s) schemes are always rejected. It is checked when the link is requested **and** again at verify time. Anything else falls back to `MAGIC_LINK_DEFAULT_REDIRECT`, then `CALLBACK_URL`; if neither is set verify returns `200` JSON instead of redirecting. The token is never placed in the redirect URL.

## Accounts and privileges

- Unknown email: a verified account with no password is created (skipped when `DISABLE_PUBLIC_SIGNUP=true`, in which case only existing accounts can sign in). `Hooks.OnSignup` runs.
- Known email (case-insensitive): the existing account is used and marked email-verified.
- **No organization membership is created.** Least-privilege choice: if verify auto-joined the tenant, anyone with an inbox could enroll themselves into any organization. The tenant binds the link to an organization and activates it for existing members; granting membership stays with invitations or the host.
- Locked or non-active accounts cannot sign in this way.

Caveat: marking an existing unverified account verified assumes nobody pre-registered the address with a password they control. Hosts that allow open password signup with unverified emails should consider this.

Link prefetchers (mail scanners) that follow `GET` links can burn a token. Hosts that see this should point the email at a UI page that calls verify on a user click.

## Rate limits

Fixed-window counters per normalized email and per client IP (`X-Forwarded-For` first hop, as elsewhere in authpad). Defaults: 5 per email and 20 per IP per 15 minutes. Over the limit the response is still `202` and nothing is sent. State is in memory, or in Redis when `REDIS_URL` is set. The generic `RATE_LIMIT_RPM` middleware is not applied to `POST /magic-link` because it answers `429`; verify uses it.

## Email

`POST https://api.resend.com/emails` with `Authorization: Bearer $RESEND_API_KEY`, from `MAGIC_LINK_FROM` (falls back to `RESEND_FROM`). Hosts can supply their own `MagicLinkMailer` (`Config.MagicLink.Mailer`).

With `RESEND_API_KEY` empty:

- not production: the link is printed to stdout (`[magic-link] … token=…`);
- production: the server refuses to start. If a mailer is wired without a key anyway, sending fails with an error log that contains no link or token.

## Storage

`magic_link_tokens` (Auth DB): `token_hash` (SHA-256, base64url; unique index), `organization_id`, `email`, `redirect_to`, `created_at`, `expires_at` (indexed), `consumed_at`. The raw 32-byte token is only ever in the email. There is no foreign key to the organization because organizations live in the IdP database. Expired rows are not purged automatically; run `DELETE FROM magic_link_tokens WHERE expires_at < now() - interval '1 day'` from a job (repository method `DeleteExpired`).

## Configuration

| Env | Config | Default |
|-----|--------|---------|
| `MAGIC_LINK_ENABLED` | `MagicLink.Enabled` | `false` |
| `MAGIC_LINK_BASE_URL` | `MagicLink.BaseURL` | required when enabled |
| `MAGIC_LINK_FROM` | `MagicLink.From` | `RESEND_FROM` |
| `RESEND_API_KEY` | `Email.ResendAPIKey` | required in production |
| `MAGIC_LINK_REDIRECT_ALLOWLIST` | `MagicLink.RedirectAllowlist` | empty (no `redirect_to` accepted) |
| `MAGIC_LINK_DEFAULT_REDIRECT` | `MagicLink.DefaultRedirectURL` | `CALLBACK_URL` |
| `MAGIC_LINK_TTL` | `MagicLink.TTL` | `15m` |
| `MAGIC_LINK_EMAIL_LIMIT` | `MagicLink.EmailLimit` | `5` (0 disables) |
| `MAGIC_LINK_IP_LIMIT` | `MagicLink.IPLimit` | `20` (0 disables) |
| `MAGIC_LINK_LIMIT_WINDOW` | `MagicLink.LimitWindow` | `15m` |

`SkipHTTPPaths: ["/magic-link"]` lets a host mount its own routes.
