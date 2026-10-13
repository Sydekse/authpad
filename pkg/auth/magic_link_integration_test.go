package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sydekse/authpad/pkg/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type chanMailer struct{ ch chan string }

func (m *chanMailer) SendMagicLink(_ context.Context, to, link string) error {
	m.ch <- to + " " + link
	return nil
}

type magicEnv struct {
	a      *auth.Auth
	h      http.Handler
	mail   *chanMailer
	conn   *pgx.Conn
	dsn    string
	org    *auth.Organization
	orgAlt *auth.Organization
}

func newMagicEnv(t *testing.T) *magicEnv { return newMagicEnvWith(t, nil) }

func newMagicEnvWith(t *testing.T, tweak func(*auth.Config)) *magicEnv {
	t.Helper()
	dsn := testDSN(t)
	ctx := context.Background()
	if err := auth.MigrateWithOptions(ctx, dsn, dsn, auth.MigrationOptions{
		AuthTable: "schema_migrations_auth", IdPTable: "schema_migrations_idp",
	}); err != nil {
		t.Fatal(err)
	}
	mail := &chanMailer{ch: make(chan string, 16)}
	cfg := auth.DefaultConfig()
	cfg.AuthDatabaseURL, cfg.IdPDatabaseURL = dsn, dsn
	cfg.Security.RateLimitRPM = 0
	cfg.Security.SessionSecret = "integration-test-session-secret-32chars"
	cfg.Tenancy.Enabled = true
	cfg.MagicLink.Enabled = true
	cfg.MagicLink.BaseURL = "https://api.example.test"
	cfg.MagicLink.RedirectAllowlist = []string{"https://app.example.com"}
	cfg.MagicLink.DefaultRedirectURL = "https://app.example.com/welcome"
	cfg.MagicLink.EmailLimit, cfg.MagicLink.IPLimit = 0, 0
	cfg.MagicLink.Mailer = mail
	if tweak != nil {
		tweak(&cfg)
	}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })

	e := &magicEnv{a: a, h: mounted(a), mail: mail, conn: conn, dsn: dsn}
	e.org, err = a.EnsureOrganization(ctx, "ml-"+uuid.NewString()[:8], "Magic Org", uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	e.orgAlt, err = a.EnsureOrganization(ctx, "ml-"+uuid.NewString()[:8], "Other Org", uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// testCodeVerifier is the RFC 7636 appendix B example verifier.
const testCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e *magicEnv) request(t *testing.T, email, tenant, redirect string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"tenant":%q,"redirect_to":%q,"code_challenge":%q}`, email, tenant, redirect, pkceChallenge(testCodeVerifier))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:4000"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// issue requests a link and returns (rawToken, verifyPath).
func (e *magicEnv) issue(t *testing.T, email, tenant, redirect string) (string, string) {
	t.Helper()
	if code, _ := e.request(t, email, tenant, redirect); code != http.StatusAccepted {
		t.Fatalf("request status %d", code)
	}
	select {
	case m := <-e.mail.ch:
		link := m[strings.Index(m, " ")+1:]
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("token"), u.RequestURI()
	case <-time.After(5 * time.Second):
		t.Fatal("no magic link mail")
		return "", ""
	}
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([a-z]+)" value="([^"]*)">`)

// page loads the GET interstitial for a link (which never consumes the token).
func (e *magicEnv) page(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "203.0.113.9:4000"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// verify does what the browser does: GET the interstitial, then submit its form.
// It returns the GET response when no form was served (bad link), else the POST's.
func (e *magicEnv) verify(path string) *httptest.ResponseRecorder {
	page := e.page(path)
	if page.Code != http.StatusOK {
		return page
	}
	form := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(page.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	u, _ := url.Parse(path)
	req := httptest.NewRequest(http.MethodPost, u.Path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:4000"
	for _, c := range page.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *magicEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.conn.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func uniqueEmail() string { return fmt.Sprintf("Attendee-%s@Example.com", uuid.NewString()[:8]) }

func TestMagicLinkFullFlow(t *testing.T) {
	e := newMagicEnv(t)
	email := uniqueEmail()
	token, path := e.issue(t, "  "+email+" ", e.org.Slug, "https://app.example.com/talks/1")

	// Only the hash is stored.
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE token_hash = $1`, token); n != 0 {
		t.Fatal("raw token found in token_hash")
	}
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE token_hash = $1 AND email = $2 AND organization_id = $3 AND consumed_at IS NULL AND expires_at > now() + interval '14 minutes' AND expires_at < now() + interval '16 minutes'`,
		auth.HashToken(token), strings.ToLower(email), e.org.ID); n != 1 {
		t.Fatal("expected one hashed, normalized, 15-minute token row")
	}
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE strpos(redirect_to, $1) > 0 OR strpos(email, $1) > 0`, token); n != 0 {
		t.Fatal("raw token leaked into another column")
	}

	rec := e.verify(path)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://app.example.com/talks/1" {
		t.Fatalf("verify = %d Location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	var sessionCookie, csrfCookie bool
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "session":
			sessionCookie = c.Value != "" && c.HttpOnly
		case "csrf_token":
			csrfCookie = c.Value != ""
		}
	}
	if !sessionCookie || !csrfCookie {
		t.Fatalf("expected session and csrf cookies, got %v", rec.Result().Cookies())
	}

	var userID uuid.UUID
	var verified bool
	if err := e.conn.QueryRow(context.Background(), `SELECT id, email_verified FROM users_auth WHERE email = $1`, strings.ToLower(email)).Scan(&userID, &verified); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("magic-link user should be email-verified")
	}
	if n := e.count(t, `SELECT count(*) FROM organization_memberships WHERE user_id = $1`, userID); n != 0 {
		t.Fatal("magic link must not create org membership")
	}
	if n := e.count(t, `SELECT count(*) FROM auth_audit_logs WHERE user_id = $1 AND action = 'login.success'`, userID); n != 1 {
		t.Fatal("expected login.success audit entry")
	}

	// The cookie is a working session.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	sr := httptest.NewRecorder()
	e.h.ServeHTTP(sr, req)
	if sr.Code != http.StatusOK {
		t.Fatalf("session check = %d %s", sr.Code, sr.Body.String())
	}

	// Reuse fails.
	if again := e.verify(path); again.Code != http.StatusBadRequest {
		t.Fatalf("reuse should be 400, got %d", again.Code)
	}
}

func TestMagicLinkMaliciousRedirectFallsBackToDefault(t *testing.T) {
	e := newMagicEnv(t)
	for _, bad := range []string{"https://evil.test/", "//evil.test", "javascript:alert(1)", "https://app.example.com@evil.test/", "/\\evil.test", "http://app.example.com/"} {
		_, path := e.issue(t, uniqueEmail(), e.org.Slug, bad)
		rec := e.verify(path)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://app.example.com/welcome" {
			t.Fatalf("redirect %q -> %d %q", bad, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestMagicLinkRedirectRevalidatedAtVerify(t *testing.T) {
	e := newMagicEnv(t)
	token, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/ok")
	// Simulate a poisoned row (or an allowlist that shrank since issue time).
	if _, err := e.conn.Exec(context.Background(), `UPDATE magic_link_tokens SET redirect_to = 'https://evil.test/' WHERE token_hash = $1`, auth.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	rec := e.verify(path)
	if rec.Header().Get("Location") != "https://app.example.com/welcome" {
		t.Fatalf("stored redirect must be re-checked, got %q", rec.Header().Get("Location"))
	}
}

func TestMagicLinkExpired(t *testing.T) {
	e := newMagicEnv(t)
	token, path := e.issue(t, uniqueEmail(), e.org.Slug, "")
	if _, err := e.conn.Exec(context.Background(), `UPDATE magic_link_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, auth.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	if rec := e.verify(path); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired token should be 400, got %d", rec.Code)
	}
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE token_hash = $1 AND consumed_at IS NULL`, auth.HashToken(token)); n != 1 {
		t.Fatal("expired token must not be consumed")
	}
}

func TestMagicLinkWrongTenant(t *testing.T) {
	e := newMagicEnv(t)
	email := uniqueEmail()
	token, _ := e.issue(t, email, e.org.Slug, "")
	for _, tenant := range []string{e.orgAlt.Slug, e.orgAlt.ID.String(), "no-such-org"} {
		rec := e.verify("/api/v1/magic-link/verify?token=" + url.QueryEscape(token) + "&tenant=" + url.QueryEscape(tenant))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("tenant %q: want 400, got %d", tenant, rec.Code)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM users_auth WHERE email = $1`, strings.ToLower(email)); n != 0 {
		t.Fatal("wrong-tenant attempts must not create a user")
	}
	// The token survives wrong-tenant attempts and works for its own tenant (by id too).
	rec := e.verify("/api/v1/magic-link/verify?token=" + url.QueryEscape(token) + "&tenant=" + e.org.ID.String())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("right tenant should succeed, got %d", rec.Code)
	}
}

func TestMagicLinkSingleUseUnderConcurrency(t *testing.T) {
	e := newMagicEnv(t)
	_, path := e.issue(t, uniqueEmail(), e.org.Slug, "")
	var ok, bad int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch e.verify(path).Code {
			case http.StatusSeeOther:
				atomic.AddInt32(&ok, 1)
			case http.StatusBadRequest:
				atomic.AddInt32(&bad, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || bad != 23 {
		t.Fatalf("want exactly 1 success, got ok=%d bad=%d", ok, bad)
	}
}

func TestMagicLinkSimultaneousFirstSignInSameEmail(t *testing.T) {
	e := newMagicEnv(t)
	email := uniqueEmail()
	var paths []string
	for i := 0; i < 4; i++ {
		_, p := e.issue(t, email, e.org.Slug, "")
		paths = append(paths, p)
	}
	var wg sync.WaitGroup
	var ok int32
	for _, p := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			if e.verify(p).Code == http.StatusSeeOther {
				atomic.AddInt32(&ok, 1)
			}
		}(p)
	}
	wg.Wait()
	if n := e.count(t, `SELECT count(*) FROM users_auth WHERE lower(email) = $1`, strings.ToLower(email)); n != 1 {
		t.Fatalf("want exactly one user, got %d", n)
	}
	if ok != 4 {
		t.Fatalf("all four distinct links should sign in, got %d", ok)
	}
}

func TestMagicLinkEnumerationIdenticalResponses(t *testing.T) {
	e := newMagicEnv(t)
	existing := uniqueEmail()
	if _, err := e.a.CreateAccount(context.Background(), auth.CreateAccountRequest{Profile: map[string]any{"name": "Test User"}, Email: strings.ToLower(existing), Password: "password1", SkipSession: true}, "127.0.0.1", "t"); err != nil {
		t.Fatal(err)
	}
	c1, b1 := e.request(t, existing, e.org.Slug, "")
	c2, b2 := e.request(t, uniqueEmail(), e.org.Slug, "")
	c3, b3 := e.request(t, existing, "no-such-org", "")
	c4, b4 := e.request(t, "not-an-email", e.org.Slug, "https://evil.test")
	if c1 != 202 || c1 != c2 || c1 != c3 || c1 != c4 || b1 != b2 || b1 != b3 || b1 != b4 {
		t.Fatalf("responses differ: %d %q / %d %q / %d %q / %d %q", c1, b1, c2, b2, c3, b3, c4, b4)
	}
}

func TestMagicLinkExistingUserKeepsAccountAndActivatesOrg(t *testing.T) {
	e := newMagicEnvWith(t, func(c *auth.Config) { c.MagicLink.AllowPasswordAccounts = true })
	ctx := context.Background()
	email := strings.ToLower(uniqueEmail())
	res, err := e.a.CreateAccount(ctx, auth.CreateAccountRequest{Profile: map[string]any{"name": "Test User"}, Email: email, Password: "password1", SkipSession: true}, "127.0.0.1", "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.AddOrganizationMember(ctx, e.org.ID, res.UserID, "member"); err != nil {
		t.Fatal(err)
	}
	_, path := e.issue(t, strings.ToUpper(email), e.org.Slug, "")
	rec := e.verify(path)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("verify = %d", rec.Code)
	}
	if n := e.count(t, `SELECT count(*) FROM users_auth WHERE lower(email) = $1`, email); n != 1 {
		t.Fatal("must reuse the existing account")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	id, err := e.a.IdentityFromRequest(req)
	if err != nil || id == nil || id.UserID != res.UserID {
		t.Fatalf("identity = %+v err=%v", id, err)
	}
	if id.ActiveOrganizationID == nil || *id.ActiveOrganizationID != e.org.ID {
		t.Fatal("member's session should have the tenant as active org")
	}
}

func TestMagicLinkLockedAccountRejected(t *testing.T) {
	e := newMagicEnvWith(t, func(c *auth.Config) { c.MagicLink.AllowPasswordAccounts = true })
	ctx := context.Background()
	email := strings.ToLower(uniqueEmail())
	res, err := e.a.CreateAccount(ctx, auth.CreateAccountRequest{Profile: map[string]any{"name": "Test User"}, Email: email, Password: "password1", SkipSession: true}, "127.0.0.1", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.LockAccount(ctx, res.UserID); err != nil {
		t.Fatal(err)
	}
	_, path := e.issue(t, email, e.org.Slug, "")
	if rec := e.verify(path); rec.Code != http.StatusBadRequest {
		t.Fatalf("locked account should get the generic 400, got %d", rec.Code)
	}
}

func TestMagicLinkMalformedBodyIs400(t *testing.T) {
	e := newMagicEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link", strings.NewReader("{nope"))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

// F5: following the emailed link (a scanner or prefetcher) must not burn it.
func TestMagicLinkGETDoesNotConsume(t *testing.T) {
	e := newMagicEnv(t)
	token, path := e.issue(t, uniqueEmail(), e.org.Slug, "")
	for i := 0; i < 3; i++ {
		rec := e.page(path)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `method="post"`) || len(rec.Result().Cookies()) != 1 {
			t.Fatalf("GET = %d cookies=%v", rec.Code, rec.Result().Cookies())
		}
		if rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("missing Referrer-Policy")
		}
	}
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE token_hash = $1 AND consumed_at IS NULL`, auth.HashToken(token)); n != 1 {
		t.Fatal("GET consumed the token")
	}
	if rec := e.verify(path); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST after GETs = %d", rec.Code)
	}
}

// A POST without the browser's nonce cookie (cross-site form post) is refused.
func TestMagicLinkPOSTWithoutNonceRefused(t *testing.T) {
	e := newMagicEnv(t)
	token, _ := e.issue(t, uniqueEmail(), e.org.Slug, "")
	form := url.Values{"token": {token}, "tenant": {e.org.Slug}, "nonce": {"forged"}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST without nonce cookie = %d", rec.Code)
	}
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE token_hash = $1 AND consumed_at IS NULL`, auth.HashToken(token)); n != 1 {
		t.Fatal("token consumed by a request without the nonce")
	}
}

func (e *magicEnv) createAccount(t *testing.T, email string, verified bool, skipSession bool) *auth.CreateAccountResult {
	t.Helper()
	res, err := e.a.CreateAccount(context.Background(), auth.CreateAccountRequest{
		Profile: map[string]any{"name": "Test User"}, Email: email, Password: "password1",
		EmailVerified: verified, SkipSession: skipSession,
	}, "127.0.0.1", "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.conn.Exec(context.Background(), `UPDATE users_auth SET email_verified = $2 WHERE id = $1`, res.UserID, verified); err != nil {
		t.Fatal(err)
	}
	return res
}

// F2: accounts with a password, and staff/admin accounts, are refused with the
// generic failure and the token is still single-use-consumed like any other.
func TestMagicLinkRefusesPasswordAndStaffAccounts(t *testing.T) {
	e := newMagicEnv(t)
	ctx := context.Background()

	pw := strings.ToLower(uniqueEmail())
	e.createAccount(t, pw, true, true)
	_, path := e.issue(t, pw, e.org.Slug, "")
	if rec := e.verify(path); rec.Code != http.StatusBadRequest || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("password account = %d cookies=%v", rec.Code, rec.Result().Cookies())
	}

	// Staff: an org owner/admin, even without a password.
	staff := strings.ToLower(uniqueEmail())
	res := e.createAccount(t, staff, true, true)
	if _, err := e.conn.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1`, res.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.AddOrganizationMember(ctx, e.org.ID, res.UserID, "owner"); err != nil {
		t.Fatal(err)
	}
	_, path = e.issue(t, staff, e.org.Slug, "")
	if rec := e.verify(path); rec.Code != http.StatusBadRequest {
		t.Fatalf("staff account = %d", rec.Code)
	}

	// A passwordless, non-staff existing account still works.
	plain := strings.ToLower(uniqueEmail())
	res = e.createAccount(t, plain, true, true)
	if _, err := e.conn.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1`, res.UserID); err != nil {
		t.Fatal(err)
	}
	_, path = e.issue(t, plain, e.org.Slug, "")
	if rec := e.verify(path); rec.Code != http.StatusSeeOther {
		t.Fatalf("passwordless account = %d", rec.Code)
	}
}

func TestMagicLinkStaffRefusedEvenWhenPasswordAccountsAllowed(t *testing.T) {
	e := newMagicEnvWith(t, func(c *auth.Config) { c.MagicLink.AllowPasswordAccounts = true })
	email := strings.ToLower(uniqueEmail())
	res := e.createAccount(t, email, true, true)
	if _, err := e.a.AddOrganizationMember(context.Background(), e.org.ID, res.UserID, "admin"); err != nil {
		t.Fatal(err)
	}
	_, path := e.issue(t, email, e.org.Slug, "")
	if rec := e.verify(path); rec.Code != http.StatusBadRequest {
		t.Fatalf("staff = %d", rec.Code)
	}
}

// F1: verifying a previously unverified account removes whatever its earlier
// registrant planted: sessions, password and MFA.
func TestMagicLinkTakesOverUnverifiedAccount(t *testing.T) {
	e := newMagicEnvWith(t, func(c *auth.Config) { c.MagicLink.AllowPasswordAccounts = true })
	ctx := context.Background()
	email := strings.ToLower(uniqueEmail())
	attacker := e.createAccount(t, email, false, false) // attacker signed up first, holds a session
	if _, err := e.conn.Exec(ctx, `INSERT INTO factors (user_id, factor_type, secret_enc, verified) VALUES ($1, 'totp', 'x', true)`, attacker.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.conn.Exec(ctx, `INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, 'h')`, attacker.UserID); err != nil {
		t.Fatal(err)
	}
	attackerSession := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
		req.Header.Set("Authorization", "Bearer "+attacker.Token)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec.Code
	}
	if attacker.Token == "" || attackerSession() == http.StatusUnauthorized {
		t.Fatal("test setup: attacker should hold a live session")
	}

	_, path := e.issue(t, email, e.org.Slug, "")
	rec := e.verify(path)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("verify = %d", rec.Code)
	}
	if attackerSession() != http.StatusUnauthorized {
		t.Fatal("attacker's pre-existing session must be revoked")
	}
	if n := e.count(t, `SELECT count(*) FROM credentials WHERE user_id = $1`, attacker.UserID); n != 0 {
		t.Fatal("password credential must be removed")
	}
	if _, err := e.a.Login(ctx, email, "password1", "127.0.0.1", "t"); err == nil {
		t.Fatal("the attacker's password must no longer log in")
	}
	if n := e.count(t, `SELECT count(*) FROM factors WHERE user_id = $1`, attacker.UserID); n != 0 {
		t.Fatal("MFA factors must be cleared")
	}
	if n := e.count(t, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1`, attacker.UserID); n != 0 {
		t.Fatal("recovery codes must be cleared")
	}
	if n := e.count(t, `SELECT count(*) FROM users_auth WHERE id = $1 AND email_verified`, attacker.UserID); n != 1 {
		t.Fatal("account should now be verified")
	}
	// The magic-link session itself is live and is not MFA-pending.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	sr := httptest.NewRecorder()
	e.h.ServeHTTP(sr, req)
	if sr.Code != http.StatusOK {
		t.Fatalf("new session = %d %s", sr.Code, sr.Body.String())
	}
}
