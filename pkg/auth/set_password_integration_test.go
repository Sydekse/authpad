package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sydekse/authpad/pkg/auth"
)

// call sends a JSON request with the session cookies of a magic-link sign-in and a matching CSRF pair.
func (e *magicEnv) call(t *testing.T, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:4000"
	for _, c := range cookies {
		if c.Name != "csrf_token" {
			req.AddCookie(c)
		}
	}
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	req.Header.Set("X-CSRF-Token", "test-csrf")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func hasPassword(t *testing.T, e *magicEnv, cookies []*http.Cookie) bool {
	t.Helper()
	rec := e.call(t, http.MethodGet, "/api/v1/account", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("account = %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		HasPassword *bool `json:"has_password"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.HasPassword == nil {
		t.Fatalf("account has no has_password: %s", rec.Body.String())
	}
	return *body.HasPassword
}

func TestSetPasswordAfterMagicLink(t *testing.T) {
	e := newMagicEnvWith(t, func(c *auth.Config) { c.MagicLink.AllowPasswordAccounts = true })
	email := strings.ToLower(uniqueEmail())
	_, path := e.issue(t, email, e.org.Slug, "https://app.example.com/")
	signedIn := e.verify(path)
	if signedIn.Code != http.StatusSeeOther {
		t.Fatalf("verify = %d", signedIn.Code)
	}
	cookies := signedIn.Result().Cookies()

	if hasPassword(t, e, cookies) {
		t.Fatal("magic-link account should start without a password")
	}
	if rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"new_password":"short"}`, cookies); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "WEAK_PASSWORD") {
		t.Fatalf("weak password = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"new_password":"correct horse battery"}`, cookies); rec.Code != http.StatusNoContent {
		t.Fatalf("set = %d %s", rec.Code, rec.Body.String())
	}
	if !hasPassword(t, e, cookies) {
		t.Fatal("has_password should be true after setting one")
	}
	if n := e.count(t, `SELECT count(*) FROM auth_audit_logs a JOIN users_auth u ON u.id = a.user_id WHERE u.email = $1 AND a.action = 'password.set'`, email); n != 1 {
		t.Fatal("expected one password.set audit entry")
	}

	// Changing it needs the current password.
	if rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"new_password":"another long passphrase"}`, cookies); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_CURRENT_PASSWORD") {
		t.Fatalf("change without current = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"current_password":"correct horse battery","new_password":"another long passphrase"}`, cookies); rec.Code != http.StatusNoContent {
		t.Fatalf("change = %d %s", rec.Code, rec.Body.String())
	}

	// The new password signs in.
	login := e.call(t, http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"another long passphrase"}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login = %d %s", login.Code, login.Body.String())
	}
	// Changing the password again signs out every other session (the login above) but keeps this one.
	if rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"current_password":"another long passphrase","new_password":"third long passphrase"}`, cookies); rec.Code != http.StatusNoContent {
		t.Fatalf("second change = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call(t, http.MethodGet, "/api/v1/account", "", login.Result().Cookies()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other session should be revoked, got %d", rec.Code)
	}
	if !hasPassword(t, e, cookies) {
		t.Fatal("this session should still work")
	}
	if n := e.count(t, `SELECT count(*) FROM auth_audit_logs a JOIN users_auth u ON u.id = a.user_id WHERE u.email = $1 AND a.action = 'password.change.failed'`, email); n != 2 {
		t.Fatalf("expected two failed-attempt audit entries, got %d", n)
	}

	// With AllowPasswordAccounts, magic links keep working for the account.
	_, again := e.issue(t, email, e.org.Slug, "https://app.example.com/")
	if rec := e.verify(again); rec.Code != http.StatusSeeOther {
		t.Fatalf("magic link after password = %d", rec.Code)
	}
}

func TestSetPasswordNeedsSessionAndCSRF(t *testing.T) {
	e := newMagicEnv(t)
	if rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"new_password":"correct horse battery"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session = %d", rec.Code)
	}
	_, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	cookies := e.verify(path).Result().Cookies()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", strings.NewReader(`{"new_password":"correct horse battery"}`))
	for _, c := range cookies {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF should be 403, got %d", rec.Code)
	}
}

func TestSetPasswordNeedsRecentSessionForFirstPassword(t *testing.T) {
	e := newMagicEnv(t)
	email := strings.ToLower(uniqueEmail())
	_, path := e.issue(t, email, e.org.Slug, "https://app.example.com/")
	cookies := e.verify(path).Result().Cookies()
	if _, err := e.conn.Exec(context.Background(), `UPDATE sessions SET created_at = now() - interval '2 hours' WHERE user_id = (SELECT id FROM users_auth WHERE email = $1)`, email); err != nil {
		t.Fatal(err)
	}
	rec := e.call(t, http.MethodPost, "/api/v1/auth/password", `{"new_password":"correct horse battery"}`, cookies)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "REAUTH_REQUIRED") {
		t.Fatalf("old session = %d %s", rec.Code, rec.Body.String())
	}
	if hasPassword(t, e, cookies) {
		t.Fatal("no password should have been set")
	}
}
