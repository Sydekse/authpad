# Hosted Pages

authpad does not render UI. Developers host signin, signup, and related pages and configure redirect URLs.

## Pages configuration

```go
cfg.Pages = auth.PagesConfig{
    SignInURL:        "https://app.example.com/signin",
    SignUpURL:        "https://app.example.com/signup",
    VerifyEmailURL:   "https://app.example.com/verify-email",
    ResetPasswordURL: "https://app.example.com/reset-password",
    CallbackURL:      "https://app.example.com/auth/callback",
    ErrorURL:         "https://app.example.com/auth/error",
    AppName:          "My App",
}
```

Environment variables: `SIGN_IN_URL`, `SIGN_UP_URL`, `VERIFY_EMAIL_URL`, `RESET_PASSWORD_URL`, `CALLBACK_URL`, `ERROR_URL`, `APP_NAME`.

## Flows

### Unauthenticated API access

Protected endpoints return `401` with a redirect hint:

```json
{
  "error": {
    "code": "NO_SESSION",
    "message": "No session token",
    "redirect": "https://app.example.com/signin?return_to=%2Fapi%2Fv1%2Faccount"
  }
}
```

### OAuth

1. Browser hits `GET /api/v1/auth/oauth/google?redirect_uri=https://app.example.com/dashboard`
2. User completes provider login
3. Callback sets session cookie and redirects to `redirect_uri?token=...` (cross-origin) or your `CallbackURL`

### Email verification

On signup (when `REQUIRE_EMAIL_VERIFICATION=true`), an email is sent with a link to your `VerifyEmailURL?token=...`. The API also exposes `GET /api/v1/auth/verify-email?token=...`.

### Password reset

Reset emails link to `ResetPasswordURL?token=...`. Your page calls `POST /api/v1/auth/password/reset`.

## Reference UI

See [examples/nextjs-hosted-pages](../examples/nextjs-hosted-pages/) for a Next.js implementation using `credentials: "include"` and the hosted-page pattern.

## CSRF

When using cookie sessions from a browser, send `X-CSRF-Token` header matching the `csrf_token` cookie on state-changing requests. Disabled with `CSRF_ENABLED=false`.
