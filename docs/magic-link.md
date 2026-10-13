# Magic-link sign-in

Passwordless sign-in for attendees of an organization (tenant). **Off by default.** Requires tenancy (`AUTHPAD_TENANCY_ENABLED=true`) and an IdP database. Apply migration `000007_magic_link_tokens` first (`000008_magic_link_codes` and `000009_magic_link_pkce` for the code flow).

## Flow

1. `POST /api/v1/magic-link` with `{ "email", "tenant", "redirect_to" }`. `tenant` is an organization slug or id. `redirect_to` is optional.
2. The user receives a link to `GET /api/v1/magic-link/verify?token=…&tenant=<slug>`. That page only asks the user to confirm; it does not consume the token.
3. The user presses the button, which `POST`s to `/api/v1/magic-link/verify`. Verify consumes the token, finds or creates the account, creates a session exactly like password login, and answers `303`.

### Request

Always `202 {"ok":true}` once the body parses as JSON (malformed JSON is `400`). The one other `400` is `INVALID_CODE_CHALLENGE`, returned when the code flow is on and `code_challenge` is missing or malformed; it does not depend on the email or tenant, so it leaks nothing. The response is identical whether the email or tenant exists, whether the request was rate limited, and whether `redirect_to` was acceptable. Work happens after the response is decided (bounded background workers), so timing does not reveal the outcome and a slow mail API never delays it. Delivery errors are logged (never with the token) and do not change the response.

Emails are trimmed and lowercased. Invalid addresses, unknown tenants, and limited requests send nothing.

### Verify

`GET /magic-link/verify` is an interstitial. Mail scanners and link prefetchers follow `GET` links, and a token consumed on GET would be burned (cookie mode: the scanner gets the session; code mode: the scanner follows the redirect into the client app, which exchanges the code). So `GET` never consumes anything. It answers `200` with a small HTML page whose form `POST`s `token`, `tenant` and a `nonce` to the same path. The page:

- loads no external resource (no scripts, images, fonts or stylesheets, only an inline style), so the token in the URL cannot reach a third party;
- is sent with `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Frame-Options: DENY` and a CSP of `default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'`;
- sets a short-lived `HttpOnly; SameSite=Strict` cookie (`authpad_ml_nonce`, scoped to the verify path) holding the same nonce as the form field. `POST` refuses a missing or different nonce **before** touching the token, so a form posted from another site cannot sign a victim in with an attacker's token (login CSRF) and cannot burn a link. The nonce is cleared after use.

`POST /magic-link/verify` (form-encoded; the token is read from the body, never the query string) is the only operation that consumes a token. Hosts that build their own page can post the same fields themselves, but must obtain the nonce cookie from the `GET` first.

- The token is hashed and consumed in one statement: `UPDATE … SET consumed_at = now() WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING …`. Two concurrent clicks cannot both succeed.
- Optional `tenant` query parameter: if present it must resolve to the organization the token was issued for. A mismatch is rejected **without** consuming the token. (Host-based tenant selection is not implemented.)
- Unknown, expired, reused, wrong-tenant, locked-account, staff/admin and password-account (see below) cases, and a missing or wrong nonce, all give the same answer: a `303` to `Pages.ErrorURL?error=invalid_link` when `ERROR_URL` is set, otherwise `400 INVALID_OR_EXPIRED_TOKEN`.
- Success sets the session cookie and `csrf_token` cookie, writes a `login.success` audit entry (`method: magic_link`), runs `Hooks.OnLogin`, and redirects. If the user has MFA, the session is created MFA-pending and must pass `/auth/mfa/challenge`, as with password login.
- If the user is already an active member of the tenant, it becomes the session's active organization.
- The response carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

### Redirects

`redirect_to` is accepted only if it is an absolute `http(s)` URL whose scheme, host and port **exactly** equal an entry in `MAGIC_LINK_REDIRECT_ALLOWLIST` (comma-separated origins such as `https://app.example.com`; default ports are normalized, entries with a path or userinfo are ignored). Userinfo, backslashes, whitespace/control characters, protocol-relative URLs, relative paths and non-http(s) schemes are always rejected. It is checked when the link is requested **and** again at verify time. Anything else falls back to `MAGIC_LINK_DEFAULT_REDIRECT`, then `CALLBACK_URL`; if neither is set verify returns `200` JSON instead of redirecting (cookie mode only; the code flow refuses to start without a destination). The token is never placed in the redirect URL.

## Code flow (apps on another domain)

authpad's session cookie is only sent to authpad's own registrable domain, so an app on a different one (for example authpad at `auth.earapa.net`, app at `earapa.sydek.dev`) cannot use it, and third-party cookies must not be relied on. With `MAGIC_LINK_CODE_FLOW=true` the session is handed over with a one-time code instead. Requires migrations `000008_magic_link_codes` and `000009_magic_link_pkce`, `MAGIC_LINK_EXCHANGE_SECRET` (at least 32 characters in production) and a redirect destination (`MAGIC_LINK_DEFAULT_REDIRECT` or `CALLBACK_URL`, an absolute http(s) URL). Config validation fails at startup without any of these. The destination check exists because the token is burned before the destination is looked up; without a fallback every link would be spent for nothing.

### PKCE (login CSRF and code-leak protection)

The code is bound to the browser that asked for the link, using PKCE (RFC 7636, S256 only):

1. The app creates a random `code_verifier` (43 to 128 characters of `A-Z a-z 0-9 - . _ ~`) and keeps it server-side, tied to the user's browser (for example in a cookie or its own session) so the callback can find it.
2. `POST /magic-link` carries `code_challenge` = `base64url(SHA-256(code_verifier))` without padding (43 characters). `code_challenge_method`, if sent, must be `S256`. It is **required** when the code flow is on: a missing or malformed challenge is `400 INVALID_CODE_CHALLENGE` and no link is sent. The challenge is stored with the token and copied to the one-time code.
3. At exchange the app sends the `code_verifier` it stored for that browser. authpad hashes it and compares in constant time.

An attacker who requests a link for their own address and sends the victim `https://app/callback?code=…` cannot complete the login for the victim's browser: the victim's browser holds no matching verifier, so the app has nothing valid to exchange with. The same goes for a code that leaks through a Referer header, history or logs: without the verifier it is useless. The app must keep the verifier per browser (not global) and drop it once used.

### Steps

1. `POST /magic-link/verify` consumes the token and creates the session exactly as before (audit, hooks, MFA-pending), but sets **no** session or CSRF cookie. It creates a code and answers `303` to the redirect URL with `code=<code>` appended to the query (existing query and fragment are kept). The redirect URL is chosen by the normal rules above (allowlist re-checked at verify, then `MAGIC_LINK_DEFAULT_REDIRECT`, then `CALLBACK_URL`).
2. The app's **server** calls `POST /magic-link/exchange` with header `X-Authpad-Exchange-Secret: <MAGIC_LINK_EXCHANGE_SECRET>` and body `{"code":"…","redirect_origin":"https://app.example.com","code_verifier":"…"}`. Never call it from a browser; the secret must not leave the app's backend.
3. Success is `200`:

```json
{"session_token":"…","expires_at":"2026-01-01T00:00:00Z","user":{"id":"…","email":"…"},"org_id":null,"is_member":false,"role":null,"mfa_required":false}
```

`org_id` is the tenant the link was issued for, **only when the user is an active member of it**; `is_member` and `role` (the member's organization role) say the same explicitly. Signing in by magic link does not create membership (see below), so for a stranger `org_id` and `role` are `null` and `is_member` is `false`. **Client apps must authorize on `is_member`, not on the fact that an exchange succeeded**: any inbox can sign in, but only members belong to the tenant. Membership is evaluated at exchange time.

The code is 32 random bytes (base64url). Only its SHA-256 hash is stored (`magic_link_codes`: `code_hash`, `session_id`, `organization_id`, `redirect_origin`, `code_challenge`, `created_at`, `expires_at`, `consumed_at`). It lives 60 seconds and is consumed with one atomic `UPDATE … WHERE consumed_at IS NULL AND expires_at > now() RETURNING …`, so concurrent exchanges produce exactly one success. It is bound to the session verify created, the tenant, and the exact origin of the redirect URL (scheme, host and port, default ports normalized). `redirect_origin` must be a bare origin and equal the bound one, and `code_verifier` must hash to the stored challenge; a mismatch of either fails **and burns** the code. A verifier that is missing or not well formed is refused before the code is consumed.

Failures:

| Status | When |
|--------|------|
| `404` | `MAGIC_LINK_EXCHANGE_SECRET` unset, or code flow off (endpoint disabled) |
| `429` | more than `MAGIC_LINK_EXCHANGE_LIMIT` (default 60) requests per client IP per minute; checked before the secret |
| `401 INVALID_EXCHANGE_SECRET` | header missing or wrong (constant-time compare; the code is not consumed) |
| `400 INVALID_BODY` | body is not JSON |
| `400 INVALID_CODE` | unknown, expired, reused, wrong origin, missing or wrong `code_verifier`, revoked/expired session, or inactive account (indistinguishable) |

### Using the session token

`session_token` is an ordinary authpad session token, the same value the cookie would have held. Exchange **replaces** the session's token hash with a fresh one (authpad never stored the raw token minted at verify), so the token from verify is dead and the exchanged one is the only valid token. Expiry is the session's normal expiry. The app validates it by sending it as a bearer token to the existing endpoints:

- `GET /api/v1/auth/session` with `Authorization: Bearer <session_token>` returns `{valid, user, token, session:{id, created_at, expires_at}, organization, org_role}` and `401` when invalid/expired/revoked, `403 MFA_REQUIRED` when MFA is pending. Bearer is accepted wherever the cookie is (`/auth/logout` to end the session, `/idp/userinfo`, `/account`, org routes).
- If session rotation is enabled (`Session.RotateInterval`), `/auth/session` may rotate the token and return the new value in `token`; the app must store it, because the old one stops working.
- Mutating routes that need CSRF accept a validated bearer token without the CSRF header.
- The app should keep the token server-side (its own cookie or store), not expose it to page scripts.

If the user has MFA, the session is MFA-pending and `mfa_required` is `true`; the token only works for `/auth/mfa/challenge` until it passes, as with the cookie flow.

Audit: `login.success` is written at verify; each exchange writes `magic_link.exchange` (with `is_member`).

## Accounts and privileges

- Unknown email: a verified account with no password is created (skipped when `DISABLE_PUBLIC_SIGNUP=true`, in which case only existing accounts can sign in). `Hooks.OnSignup` runs.
- Known email (case-insensitive): the existing account is used, subject to the rules below.
- **Staff and admin accounts are refused.** An account the staff classifier flags (platform admin role, or an organization role in `AUTHPAD_TENANCY_STAFF_ROLES`, default `owner`/`admin`) cannot sign in by magic link, because that would replace the password factor with inbox access alone. They get the same generic failure as any invalid link, and the token is spent.
- **Accounts with a password credential are refused** unless `MAGIC_LINK_ALLOW_PASSWORD_ACCOUNTS=true`. Magic link is for attendees who have no password. Staff are refused even when this is on.
- **Account takeover protection.** If the account is not yet email-verified, the link is the first proof that the person holds the inbox, and whoever registered the address earlier may have set a password, started sessions or enrolled MFA. So before marking it verified, verify (a) revokes **all** its sessions, (b) deletes its password credential, and (c) deletes its MFA factors and recovery codes. Password login then works only after the owner sets a password through the normal reset flow (`/auth/password/reset-request`); a reset is now allowed for a verified account that has no password, and sets one. With `MAGIC_LINK_ALLOW_PASSWORD_ACCOUNTS=false` (default) an unverified password account is refused outright, so this wipe only happens when that opt-in is on, or for accounts that had no password to begin with (for example OAuth-only). If the wipe fails the sign-in fails.
- **No organization membership is created.** Least-privilege choice: if verify auto-joined the tenant, anyone with an inbox could enroll themselves into any organization. The tenant binds the link to an organization and activates it for existing members; granting membership stays with invitations or the host. In the code flow the exchange response says whether the user is a member (see above).
- Locked or non-active accounts cannot sign in this way.

## Rate limits

Fixed-window counters per normalized email and per client IP (see "Client IP and reverse proxies"). Defaults: 5 per email and 20 per IP per 15 minutes. Over the limit the response is still `202` and nothing is sent. State is in memory, or in Redis when `REDIS_URL` is set. The generic `RATE_LIMIT_RPM` middleware is not applied to `POST /magic-link` because it answers `429`; verify uses it.

## Client IP and reverse proxies

The per-IP magic-link limits, the exchange limit, the generic rate limiter and audit entries all use one client-address function. By default it is the connection's remote address, and `X-Forwarded-For` is **ignored**, so a caller cannot dodge a limit by rotating the header.

Behind a reverse proxy (Traefik, nginx, a load balancer) the remote address is the proxy, so every client would share one limit. Set `TRUSTED_PROXY_CIDRS` to the proxy's address range, comma-separated CIDRs or single IPs (for example the Docker network Traefik runs on):

```
TRUSTED_PROXY_CIDRS=172.18.0.0/16
```

`X-Forwarded-For` is then believed only when the connection comes from inside that set. The header is read from the right: trusted proxy hops are skipped and the first address that is not a trusted proxy is the client, so entries a caller prepends to the header are ignored. A connection from outside the set still gets its own remote address. Invalid entries fail startup. Config field: `Security.TrustedProxyCIDRs`.

Make sure the proxy overwrites or appends to `X-Forwarded-For` rather than passing a client's value through untouched, and that the authpad port is reachable only through it.

## Email

`POST https://api.resend.com/emails` with `Authorization: Bearer $RESEND_API_KEY`, from `MAGIC_LINK_FROM` (falls back to `RESEND_FROM`). Hosts can supply their own `MagicLinkMailer` (`Config.MagicLink.Mailer`).

With `RESEND_API_KEY` empty:

- `ENV=development` only: the link is printed to stdout (`[magic-link] … token=…`). Any other value, including `production`, `prod`, `staging` and empty, never prints a link. A dev mailer not created by the development path redacts the token (`token=REDACTED`);
- every other `ENV`: the server refuses to start. If a mailer is wired without a key anyway, sending fails with an error log that contains no link or token.

## Storage

`magic_link_tokens` (Auth DB): `token_hash` (SHA-256, base64url; unique index), `organization_id`, `email`, `redirect_to`, `created_at`, `expires_at` (indexed), `consumed_at`. The raw 32-byte token is only ever in the email. There is no foreign key to the organization because organizations live in the IdP database. Expired token and code rows are deleted by a background job inside the server (once at startup, then hourly, stopped by `Close`), so the tables, and the emails and redirect URLs in them, do not grow without bound.

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
| `MAGIC_LINK_ALLOW_PASSWORD_ACCOUNTS` | `MagicLink.AllowPasswordAccounts` | `false` (accounts with a password are refused; staff always are) |
| `TRUSTED_PROXY_CIDRS` | `Security.TrustedProxyCIDRs` | empty (`X-Forwarded-For` ignored) |
| `ENV` | `Env` | `development`; the dev link printer exists only for exactly `development` |

`SkipHTTPPaths: ["/magic-link"]` lets a host mount its own routes.

## Known limitations

These were reviewed and are accepted for now.

- **Redirect allowlist is global (F6).** `MAGIC_LINK_REDIRECT_ALLOWLIST` is one list for all tenants and only constrains the origin, not the path. A link for tenant B can carry a `redirect_to` pointing at tenant A's app, which then receives a code and session for B, and a requester can choose any path on an allowed origin (a page with an open redirect or third-party resources would receive the code in its URL; PKCE blunts, but does not remove, this). Only list origins whose callback handles any tenant and any path safely. Per-organization origins and registered callback paths are not implemented.
- **One shared exchange secret (F7).** All client apps share `MAGIC_LINK_EXCHANGE_SECRET`, and the caller states its own `redirect_origin`, so origin binding does not stop a holder of the secret from redeeming codes meant for another app. `/exchange` returns a full authpad bearer token, not an app-scoped credential. Keep the secret on trusted backends only. Per-client secrets that fix the allowed origins are not implemented.
- **Redis limiter (F9).** The Redis window limiter does `INCR` then `EXPIRE` non-atomically, so a crash between them can leave a counter that never expires and keeps that email or IP locked out until the key is removed. It fails open on any Redis error. Without Redis the limiter is per process, so limits multiply with the number of replicas. Use Redis when running more than one instance.
- **In-flight cap (F10).** At most 64 link requests are processed at once; further requests are dropped silently and still answered `202`. A flood can therefore keep legitimate links from being sent. The per-IP and per-email limits and the proxy settings above reduce this, but there is no queue or metric yet.
