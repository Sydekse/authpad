# Magic-link sign-in

Passwordless sign-in for attendees of an organization (tenant). **Off by default.** Requires tenancy (`AUTHPAD_TENANCY_ENABLED=true`) and an IdP database. Apply migration `000007_magic_link_tokens` first (`000008_magic_link_codes` for the code flow).

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

## Code flow (apps on another domain)

authpad's session cookie is only sent to authpad's own registrable domain, so an app on a different one (for example authpad at `auth.earapa.net`, app at `earapa.sydek.dev`) cannot use it, and third-party cookies must not be relied on. With `MAGIC_LINK_CODE_FLOW=true` the session is handed over with a one-time code instead. Requires migration `000008_magic_link_codes` and `MAGIC_LINK_EXCHANGE_SECRET` (config validation fails without it; at least 32 characters in production).

1. `GET /magic-link/verify` consumes the token and creates the session exactly as before (audit, hooks, MFA-pending), but sets **no** session or CSRF cookie. It creates a code and answers `303` to the redirect URL with `code=<code>` appended to the query (existing query and fragment are kept). The redirect URL is chosen by the normal rules above (allowlist re-checked at verify, then `MAGIC_LINK_DEFAULT_REDIRECT`, then `CALLBACK_URL`). If none is available the answer is `400 NO_REDIRECT` (the link is already spent) and no session is left usable.
2. The app's **server** calls `POST /magic-link/exchange` with header `X-Authpad-Exchange-Secret: <MAGIC_LINK_EXCHANGE_SECRET>` and body `{"code":"…","redirect_origin":"https://app.example.com"}`. Never call it from a browser; the secret must not leave the app's backend.
3. Success is `200`:

```json
{"session_token":"…","expires_at":"2026-01-01T00:00:00Z","user":{"id":"…","email":"…"},"org_id":"…","mfa_required":false}
```

The code is 32 random bytes (base64url). Only its SHA-256 hash is stored (`magic_link_codes`: `code_hash`, `session_id`, `organization_id`, `redirect_origin`, `created_at`, `expires_at`, `consumed_at`). It lives 60 seconds and is consumed with one atomic `UPDATE … WHERE consumed_at IS NULL AND expires_at > now() RETURNING …`, so concurrent exchanges produce exactly one success. It is bound to the session verify created, the tenant, and the exact origin of the redirect URL (scheme, host and port, default ports normalized). `redirect_origin` must be a bare origin and equal the bound one; a mismatch fails **and burns** the code.

Failures:

| Status | When |
|--------|------|
| `404` | `MAGIC_LINK_EXCHANGE_SECRET` unset, or code flow off (endpoint disabled) |
| `429` | more than `MAGIC_LINK_EXCHANGE_LIMIT` (default 60) requests per client IP per minute; checked before the secret |
| `401 INVALID_EXCHANGE_SECRET` | header missing or wrong (constant-time compare; the code is not consumed) |
| `400 INVALID_BODY` | body is not JSON |
| `400 INVALID_CODE` | unknown, expired, reused, wrong origin, revoked/expired session, or inactive account (indistinguishable) |

### Using the session token

`session_token` is an ordinary authpad session token, the same value the cookie would have held. Exchange **replaces** the session's token hash with a fresh one (authpad never stored the raw token minted at verify), so the token from verify is dead and the exchanged one is the only valid token. Expiry is the session's normal expiry. The app validates it by sending it as a bearer token to the existing endpoints:

- `GET /api/v1/auth/session` with `Authorization: Bearer <session_token>` returns `{valid, user, token, session:{id, created_at, expires_at}, organization, org_role}` and `401` when invalid/expired/revoked, `403 MFA_REQUIRED` when MFA is pending. Bearer is accepted wherever the cookie is (`/auth/logout` to end the session, `/idp/userinfo`, `/account`, org routes).
- If session rotation is enabled (`Session.RotateInterval`), `/auth/session` may rotate the token and return the new value in `token`; the app must store it, because the old one stops working.
- Mutating routes that need CSRF accept a validated bearer token without the CSRF header.
- The app should keep the token server-side (its own cookie or store), not expose it to page scripts.

If the user has MFA, the session is MFA-pending and `mfa_required` is `true`; the token only works for `/auth/mfa/challenge` until it passes, as with the cookie flow.

Audit: `login.success` is written at verify; each exchange writes `magic_link.exchange`. Expired codes are not purged automatically (`DELETE FROM magic_link_codes WHERE expires_at < now() - interval '1 day'`, repository method `DeleteExpired`).

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
| `MAGIC_LINK_CODE_FLOW` | `MagicLink.CodeFlow` | `false` |
| `MAGIC_LINK_EXCHANGE_SECRET` | `MagicLink.ExchangeSecret` | empty (exchange disabled; required when code flow is on) |
| `MAGIC_LINK_EXCHANGE_LIMIT` | `MagicLink.ExchangeLimit` | `60` per IP per minute (0 disables) |

`SkipHTTPPaths: ["/magic-link"]` lets a host mount its own routes.
