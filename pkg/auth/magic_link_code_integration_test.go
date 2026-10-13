package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Sydekse/authpad/pkg/auth"
)

const testExchangeSecret = "integration-exchange-secret-0123456789"

func newCodeEnv(t *testing.T) *magicEnv {
	return newMagicEnvWith(t, func(c *auth.Config) {
		c.MagicLink.CodeFlow = true
		c.MagicLink.ExchangeSecret = testExchangeSecret
		c.MagicLink.ExchangeLimit = 0
	})
}

func (e *magicEnv) exchange(secret *string, code, origin string) *httptest.ResponseRecorder {
	return e.exchangeWith(secret, code, origin, testCodeVerifier)
}

func (e *magicEnv) exchangeWith(secret *string, code, origin, verifier string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"code": code, "redirect_origin": origin, "code_verifier": verifier})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link/exchange", strings.NewReader(string(body)))
	req.RemoteAddr = "203.0.113.50:4000"
	if secret != nil {
		req.Header.Set("X-Authpad-Exchange-Secret", *secret)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// verifyCode runs verify and returns the code from the redirect.
func (e *magicEnv) verifyCode(t *testing.T, path string) (code string, loc *url.URL, rec *httptest.ResponseRecorder) {
	t.Helper()
	rec = e.verify(path)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("code"), loc, rec
}

func TestCodeFlowVerifyAppendsCodeAndSetsNoCookie(t *testing.T) {
	e := newCodeEnv(t)
	token, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/talks/1?lang=en")
	code, loc, rec := e.verifyCode(t, path)
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://app.example.com/talks/1" || loc.Query().Get("lang") != "en" || code == "" {
		t.Fatalf("Location = %s", loc)
	}
	if len(nonNonceCookies(rec.Result().Cookies())) != 0 {
		t.Fatalf("code flow must not set cookies: %v", rec.Result().Cookies())
	}
	if strings.Contains(loc.String(), token) {
		t.Fatal("magic token leaked into redirect")
	}
	// Only the hash is stored; 60s expiry; bound to origin and tenant.
	if n := e.count(t, `SELECT count(*) FROM magic_link_codes WHERE code_hash = $1`, code); n != 0 {
		t.Fatal("raw code stored")
	}
	if n := e.count(t, `SELECT count(*) FROM magic_link_codes WHERE code_hash = $1 AND organization_id = $2 AND redirect_origin = 'https://app.example.com:443' AND consumed_at IS NULL AND expires_at > now() + interval '55 seconds' AND expires_at <= now() + interval '61 seconds'`,
		auth.HashToken(code), e.org.ID); n != 1 {
		t.Fatal("expected one hashed code row bound to origin/tenant with 60s expiry")
	}
}

func TestCodeFlowStillEnforcesRedirectAllowlist(t *testing.T) {
	e := newCodeEnv(t)
	for _, bad := range []string{"https://evil.test/", "//evil.test", "https://app.example.com@evil.test/", "http://app.example.com/"} {
		_, path := e.issue(t, uniqueEmail(), e.org.Slug, bad)
		code, loc, _ := e.verifyCode(t, path)
		if loc.Host != "app.example.com" || loc.Path != "/welcome" || code == "" {
			t.Fatalf("redirect %q -> %s", bad, loc)
		}
	}
	// Poisoned stored redirect is re-checked; the code binds to the safe origin.
	token, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/ok")
	if _, err := e.conn.Exec(context.Background(), `UPDATE magic_link_tokens SET redirect_to = 'https://evil.test/' WHERE token_hash = $1`, auth.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	code, loc, _ := e.verifyCode(t, path)
	if loc.Host != "app.example.com" {
		t.Fatalf("Location = %s", loc)
	}
	if rec := e.exchange(&[]string{testExchangeSecret}[0], code, "https://evil.test"); rec.Code != http.StatusBadRequest {
		t.Fatalf("evil origin exchange = %d", rec.Code)
	}
}

func TestCodeFlowExchangeSuccessAndSessionToken(t *testing.T) {
	e := newCodeEnv(t)
	email := strings.ToLower(uniqueEmail())
	_, path := e.issue(t, email, e.org.Slug, "https://app.example.com/")
	code, _, _ := e.verifyCode(t, path)

	secret := testExchangeSecret
	rec := e.exchange(&secret, code, "https://app.example.com")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
		User         struct{ ID, Email string }
		OrgID        *string `json:"org_id"`
		IsMember     bool    `json:"is_member"`
		Role         *string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SessionToken == "" || out.ExpiresAt == "" || out.User.Email != email || out.User.ID == "" {
		t.Fatalf("bad body: %s", rec.Body.String())
	}
	// F3: signing in does not make the user a member, so the tenant is not reported.
	if out.OrgID != nil || out.IsMember || out.Role != nil || !strings.Contains(rec.Body.String(), `"org_id":null`) {
		t.Fatalf("non-member must get null org_id/role and is_member=false: %s", rec.Body.String())
	}

	// The token is a normal bearer session token.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	req.Header.Set("Authorization", "Bearer "+out.SessionToken)
	sr := httptest.NewRecorder()
	e.h.ServeHTTP(sr, req)
	if sr.Code != http.StatusOK || !strings.Contains(sr.Body.String(), out.User.ID) {
		t.Fatalf("session check = %d %s", sr.Code, sr.Body.String())
	}

	// Reuse of the code fails and does not mint another token.
	if again := e.exchange(&secret, code, "https://app.example.com"); again.Code != http.StatusBadRequest {
		t.Fatalf("code reuse = %d", again.Code)
	}
}

func TestCodeFlowExchangeWrongOriginBurnsCode(t *testing.T) {
	e := newCodeEnv(t)
	secret := testExchangeSecret
	for _, bad := range []string{"https://evil.test", "http://app.example.com", "https://app.example.com:8443", ""} {
		_, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
		code, _, _ := e.verifyCode(t, path)
		if rec := e.exchange(&secret, code, bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("origin %q = %d", bad, rec.Code)
		}
		if rec := e.exchange(&secret, code, "https://app.example.com"); rec.Code != http.StatusBadRequest {
			t.Fatalf("origin %q: code should be burned, got %d", bad, rec.Code)
		}
	}
}

func TestCodeFlowExchangeBadSecret(t *testing.T) {
	e := newCodeEnv(t)
	_, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	code, _, _ := e.verifyCode(t, path)
	wrong := "wrong"
	for name, s := range map[string]*string{"missing": nil, "wrong": &wrong} {
		if rec := e.exchange(s, code, "https://app.example.com"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s secret = %d", name, rec.Code)
		}
	}
	// Bad-secret attempts must not consume the code.
	good := testExchangeSecret
	if rec := e.exchange(&good, code, "https://app.example.com"); rec.Code != http.StatusOK {
		t.Fatalf("code should survive bad-secret attempts, got %d", rec.Code)
	}
}

func TestCodeFlowExchangeExpired(t *testing.T) {
	e := newCodeEnv(t)
	_, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	code, _, _ := e.verifyCode(t, path)
	if _, err := e.conn.Exec(context.Background(), `UPDATE magic_link_codes SET expires_at = now() - interval '1 second' WHERE code_hash = $1`, auth.HashToken(code)); err != nil {
		t.Fatal(err)
	}
	secret := testExchangeSecret
	if rec := e.exchange(&secret, code, "https://app.example.com"); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired code = %d", rec.Code)
	}
}

func TestCodeFlowExchangeSingleUseUnderConcurrency(t *testing.T) {
	e := newCodeEnv(t)
	_, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	code, _, _ := e.verifyCode(t, path)
	secret := testExchangeSecret
	var ok, bad int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch e.exchange(&secret, code, "https://app.example.com").Code {
			case http.StatusOK:
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

func TestCodeFlowRevokedSessionCannotBeExchanged(t *testing.T) {
	e := newCodeEnv(t)
	_, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	code, _, _ := e.verifyCode(t, path)
	if _, err := e.conn.Exec(context.Background(), `UPDATE sessions SET revoked = true WHERE id = (SELECT session_id FROM magic_link_codes WHERE code_hash = $1)`, auth.HashToken(code)); err != nil {
		t.Fatal(err)
	}
	secret := testExchangeSecret
	if rec := e.exchange(&secret, code, "https://app.example.com"); rec.Code != http.StatusBadRequest {
		t.Fatalf("revoked session = %d", rec.Code)
	}
}

// F3: an active member gets org_id, is_member and role.
func TestCodeFlowExchangeReportsMembership(t *testing.T) {
	e := newCodeEnv(t)
	ctx := context.Background()
	email := strings.ToLower(uniqueEmail())
	res := e.createAccount(t, email, true, true)
	if _, err := e.conn.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1`, res.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.AddOrganizationMember(ctx, e.org.ID, res.UserID, "member"); err != nil {
		t.Fatal(err)
	}
	_, path := e.issue(t, email, e.org.Slug, "https://app.example.com/")
	code, _, _ := e.verifyCode(t, path)
	secret := testExchangeSecret
	rec := e.exchange(&secret, code, "https://app.example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		OrgID    *string `json:"org_id"`
		IsMember bool    `json:"is_member"`
		Role     string  `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OrgID == nil || *out.OrgID != e.org.ID.String() || !out.IsMember || out.Role != "member" {
		t.Fatalf("member body: %s", rec.Body.String())
	}
}

// F4: the request must carry a challenge, and exchange must present its verifier.
func TestCodeFlowPKCE(t *testing.T) {
	e := newCodeEnv(t)
	secret := testExchangeSecret

	body := fmt.Sprintf(`{"email":%q,"tenant":%q}`, uniqueEmail(), e.org.Slug)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link", strings.NewReader(body))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("request without code_challenge = %d", rec.Code)
	}

	token, path := e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	if n := e.count(t, `SELECT count(*) FROM magic_link_tokens WHERE token_hash = $1 AND code_challenge = $2`, auth.HashToken(token), pkceChallenge(testCodeVerifier)); n != 1 {
		t.Fatal("challenge must be stored with the token")
	}
	code, _, _ := e.verifyCode(t, path)
	if n := e.count(t, `SELECT count(*) FROM magic_link_codes WHERE code_hash = $1 AND code_challenge = $2`, auth.HashToken(code), pkceChallenge(testCodeVerifier)); n != 1 {
		t.Fatal("challenge must be copied to the code")
	}
	for name, v := range map[string]string{"wrong": "A" + testCodeVerifier[1:], "missing": ""} {
		if r := e.exchangeWith(&secret, code, "https://app.example.com", v); r.Code != http.StatusBadRequest {
			t.Fatalf("%s verifier = %d", name, r.Code)
		}
	}
	// Wrong verifier burned the code (missing was refused before consuming, but the first attempt burned it).
	if r := e.exchange(&secret, code, "https://app.example.com"); r.Code != http.StatusBadRequest {
		t.Fatalf("code should be burned by a wrong verifier, got %d", r.Code)
	}

	_, path = e.issue(t, uniqueEmail(), e.org.Slug, "https://app.example.com/")
	code, _, _ = e.verifyCode(t, path)
	if r := e.exchange(&secret, code, "https://app.example.com"); r.Code != http.StatusOK {
		t.Fatalf("matching verifier = %d %s", r.Code, r.Body.String())
	}
}
