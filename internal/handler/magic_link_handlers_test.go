package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/idp"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/google/uuid"
)

type nopStore struct{}

func (nopStore) Create(context.Context, *auth_repo.MagicLinkToken) error { return nil }
func (nopStore) Consume(context.Context, string, *uuid.UUID) (*auth_repo.MagicLinkToken, error) {
	return nil, nil
}

type oneTenant struct{ org *idp.Organization }

func (o oneTenant) ResolveTenant(_ context.Context, t string) (*idp.Organization, error) {
	if t == o.org.Slug {
		return o.org, nil
	}
	return nil, nil
}

type countMailer struct{ n int }

func (c *countMailer) SendMagicLink(context.Context, string, string) error { c.n++; return nil }

func TestMagicLinkRequestResponsesAreIdentical(t *testing.T) {
	cfg := &apptypes.AppConfig{MagicLink: apptypes.MagicLinkConfig{BaseURL: "https://api.example.com", EmailLimit: 1, IPLimit: 3, LimitWindow: 1e9 * 900}}
	mailer := &countMailer{}
	svc := service.NewMagicLinkService(cfg, nopStore{}, oneTenant{&idp.Organization{ID: uuid.New(), Slug: "acme"}},
		mailer, security.NewMemoryWindowLimiter(), nil, nil)
	h := &MagicLinkHandlers{Links: svc, Cfg: cfg}

	post := func(body, ip string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/magic-link", strings.NewReader(body))
		req.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.Request(rec, req)
		return rec.Code, rec.Body.String()
	}
	bodies := []string{
		`{"email":"exists@example.com","tenant":"acme"}`,                               // valid, delivered
		`{"email":"exists@example.com","tenant":"acme"}`,                               // rate limited (email)
		`{"email":"nobody@example.com","tenant":"acme"}`,                               // unknown user (same path)
		`{"email":"x@example.com","tenant":"nope"}`,                                    // unknown tenant
		`{"email":"garbage","tenant":"acme"}`,                                          // invalid email
		`{"email":"y@example.com","tenant":"acme","redirect_to":"https://evil.test/"}`, // bad redirect
		`{"email":"z@example.com","tenant":"acme"}`,                                    // IP limited by now
	}
	var wantCode int
	var wantBody string
	for i, b := range bodies {
		code, body := post(b, "5.5.5.5")
		svc.Wait()
		if i == 0 {
			wantCode, wantBody = code, body
		}
		if code != http.StatusAccepted || code != wantCode || body != wantBody {
			t.Fatalf("case %d: got %d %q, want %d %q", i, code, body, wantCode, wantBody)
		}
	}
	if mailer.n != 2 { // exists@ and nobody@ (user existence is never consulted)
		t.Fatalf("unexpected number of mails: %d", mailer.n)
	}
	if code, _ := post(`{not json`, "5.5.5.5"); code != http.StatusBadRequest {
		t.Fatalf("malformed JSON should be 400, got %d", code)
	}
}

func TestAppendCodePreservesQueryAndFragment(t *testing.T) {
	for in, want := range map[string]string{
		"https://app.example.com/cb":                 "https://app.example.com/cb?code=abc",
		"https://app.example.com/cb?next=%2Ftalks&a": "https://app.example.com/cb?next=%2Ftalks&a&code=abc",
		"https://app.example.com/cb?x=1#frag":        "https://app.example.com/cb?x=1&code=abc#frag",
	} {
		if got := appendCode(in, "abc"); got != want {
			t.Errorf("appendCode(%q) = %q, want %q", in, got, want)
		}
	}
}

type nopCodeStore struct{}

func (nopCodeStore) Create(context.Context, *auth_repo.MagicLinkCode) error { return nil }
func (nopCodeStore) Consume(context.Context, string) (*auth_repo.MagicLinkCode, error) {
	return nil, nil
}

func exchangeHandler(secret string, limit int) *MagicLinkHandlers {
	cfg := &apptypes.AppConfig{MagicLink: apptypes.MagicLinkConfig{CodeFlow: true, ExchangeSecret: secret, ExchangeLimit: limit}}
	svc := service.NewMagicLinkService(cfg, nopStore{}, oneTenant{&idp.Organization{ID: uuid.New(), Slug: "acme"}},
		&countMailer{}, security.NewMemoryWindowLimiter(), nil, nil)
	svc.EnableCodeFlow(nopCodeStore{}, &service.AuthService{})
	return &MagicLinkHandlers{Links: svc, Cfg: cfg}
}

func postExchange(h *MagicLinkHandlers, secret *string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/magic-link/exchange", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.7:1"
	if secret != nil {
		req.Header.Set("X-Authpad-Exchange-Secret", *secret)
	}
	rec := httptest.NewRecorder()
	h.Exchange(rec, req)
	return rec
}

func TestExchangeSecretHandling(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	body := `{"code":"x","redirect_origin":"https://app.example.com"}`
	str := func(s string) *string { return &s }

	// Unset secret: endpoint disabled, even when the caller sends a header.
	if rec := postExchange(exchangeHandler("", 0), str(""), body); rec.Code != http.StatusNotFound {
		t.Fatalf("unset secret: %d", rec.Code)
	}
	h := exchangeHandler(secret, 0)
	for name, hdr := range map[string]*string{"missing": nil, "empty": str(""), "wrong": str("nope"), "prefix": str(secret[:10]), "longer": str(secret + "x")} {
		if rec := postExchange(h, hdr, body); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s secret: %d", name, rec.Code)
		}
	}
	// Right secret reaches the code check (unknown code -> 400, bad JSON -> 400).
	if rec := postExchange(h, str(secret), body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_CODE") {
		t.Fatalf("right secret, unknown code: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postExchange(h, str(secret), "{nope"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_BODY") {
		t.Fatalf("bad json: %d %s", rec.Code, rec.Body.String())
	}
}

func TestExchangeRateLimitedPerIP(t *testing.T) {
	h := exchangeHandler("0123456789abcdef0123456789abcdef", 3)
	for i := 0; i < 3; i++ {
		if rec := postExchange(h, nil, `{}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	if rec := postExchange(h, nil, `{}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt should be limited, got %d", rec.Code)
	}
}

type countStore struct{ consumes atomic.Int32 }

func (*countStore) Create(context.Context, *auth_repo.MagicLinkToken) error { return nil }
func (c *countStore) Consume(context.Context, string, *uuid.UUID) (*auth_repo.MagicLinkToken, error) {
	c.consumes.Add(1)
	return nil, nil
}

func verifyHandler(store *countStore) *MagicLinkHandlers {
	cfg := &apptypes.AppConfig{APIBasePath: "/api/v1", Pages: apptypes.PagesConfig{AppName: "Acme"}}
	svc := service.NewMagicLinkService(cfg, store, oneTenant{&idp.Organization{ID: uuid.New(), Slug: "acme"}},
		&countMailer{}, security.NewMemoryWindowLimiter(), nil, nil)
	return &MagicLinkHandlers{Links: svc, Cfg: cfg}
}

var hiddenField = regexp.MustCompile(`<input type="hidden" name="([a-z]+)" value="([^"]*)">`)

// F5: GET renders a confirmation page and never consumes the token.
func TestVerifyGETRendersInterstitialAndDoesNotConsume(t *testing.T) {
	store := &countStore{}
	h := verifyHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/magic-link/verify?token=TOKEN123&tenant=acme", nil)
	rec := httptest.NewRecorder()
	h.VerifyPage(rec, req)

	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if store.consumes.Load() != 0 {
		t.Fatal("GET must not consume the token")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", rec.Header())
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<form method="post" action="/api/v1/magic-link/verify">`) {
		t.Fatalf("no POST form to the verify path: %s", body)
	}
	// Nothing may load a third-party resource while the token sits in the URL.
	for _, bad := range []string{"src=", "href=", "http://", "https://", "<script", "<link", "<img", "@import", "url("} {
		if strings.Contains(body, bad) {
			t.Fatalf("page must not contain %q", bad)
		}
	}
	fields := map[string]string{}
	for _, m := range hiddenField.FindAllStringSubmatch(body, -1) {
		fields[m[1]] = m[2]
	}
	if fields["token"] != "TOKEN123" || fields["tenant"] != "acme" || fields["nonce"] == "" {
		t.Fatalf("hidden fields = %v", fields)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == magicNonceCookie {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != fields["nonce"] || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/v1/magic-link/verify" {
		t.Fatalf("nonce cookie = %+v", cookie)
	}
}

func TestVerifyPageEscapesTokenAndRejectsMissing(t *testing.T) {
	h := verifyHandler(&countStore{})
	rec := httptest.NewRecorder()
	h.VerifyPage(rec, httptest.NewRequest(http.MethodGet, "/v?token="+url.QueryEscape(`"><script>alert(1)</script>`), nil))
	if strings.Contains(rec.Body.String(), "<script>alert") {
		t.Fatal("token must be HTML-escaped")
	}
	for _, target := range []string{"/v", "/v?token=", "/v?token=" + strings.Repeat("a", 300)} {
		rec := httptest.NewRecorder()
		h.VerifyPage(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "<form") {
			t.Fatalf("%s: %d", target, rec.Code)
		}
	}
}

func postVerify(h *MagicLinkHandlers, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.Verify(rec, req)
	return rec
}

// Only a POST carrying this browser's nonce reaches the store; a cross-site form
// post (no cookie, or a different nonce) is rejected without consuming anything.
func TestVerifyPOSTRequiresNonceThenConsumes(t *testing.T) {
	store := &countStore{}
	h := verifyHandler(store)
	nonce := &http.Cookie{Name: magicNonceCookie, Value: "n0nce"}

	for name, tc := range map[string]struct {
		form   url.Values
		cookie *http.Cookie
	}{
		"no cookie":      {url.Values{"token": {"t"}, "nonce": {"n0nce"}}, nil},
		"no form nonce":  {url.Values{"token": {"t"}}, nonce},
		"wrong nonce":    {url.Values{"token": {"t"}, "nonce": {"other"}}, nonce},
		"token in query": {url.Values{"nonce": {"n0nce"}}, nonce}, // token only in the URL is ignored
	} {
		rec := postVerify(h, tc.form, tc.cookie)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_OR_EXPIRED_TOKEN") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if name != "token in query" && store.consumes.Load() != 0 {
			t.Fatalf("%s: token consumed without a valid nonce", name)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/magic-link/verify?token=queryTok", strings.NewReader(url.Values{"nonce": {"n0nce"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(nonce)
	rec := httptest.NewRecorder()
	h.Verify(rec, req)
	if store.consumes.Load() != 0 {
		t.Fatal("a token supplied only in the query string must not be consumed")
	}

	rec = postVerify(h, url.Values{"token": {"t"}, "nonce": {"n0nce"}}, nonce)
	if store.consumes.Load() != 1 {
		t.Fatal("a POST with the matching nonce should reach Consume")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing Referrer-Policy on POST")
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == magicNonceCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("nonce cookie should be cleared after use")
	}
}

func codeFlowRequestHandler() (*MagicLinkHandlers, *countMailer) {
	cfg := &apptypes.AppConfig{MagicLink: apptypes.MagicLinkConfig{CodeFlow: true, BaseURL: "https://api.example.com", ExchangeSecret: "s"}}
	m := &countMailer{}
	svc := service.NewMagicLinkService(cfg, nopStore{}, oneTenant{&idp.Organization{ID: uuid.New(), Slug: "acme"}},
		m, security.NewMemoryWindowLimiter(), nil, nil)
	svc.EnableCodeFlow(nopCodeStore{}, &service.AuthService{})
	return &MagicLinkHandlers{Links: svc, Cfg: cfg}, m
}

// F4: code flow requires a well-formed S256 challenge on the request.
func TestRequestRequiresPKCEChallengeInCodeFlow(t *testing.T) {
	h, mailer := codeFlowRequestHandler()
	good := service.PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	post := func(body string) int {
		rec := httptest.NewRecorder()
		h.Request(rec, httptest.NewRequest(http.MethodPost, "/magic-link", strings.NewReader(body)))
		h.Links.Wait()
		return rec.Code
	}
	for name, body := range map[string]string{
		"missing":      `{"email":"a@example.com","tenant":"acme"}`,
		"malformed":    `{"email":"a@example.com","tenant":"acme","code_challenge":"abc"}`,
		"plain method": `{"email":"a@example.com","tenant":"acme","code_challenge":"` + good + `","code_challenge_method":"plain"}`,
	} {
		if code := post(body); code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", name, code)
		}
	}
	if mailer.n != 0 {
		t.Fatal("nothing may be sent for a rejected request")
	}
	if code := post(`{"email":"a@example.com","tenant":"acme","code_challenge":"` + good + `","code_challenge_method":"S256"}`); code != http.StatusAccepted {
		t.Fatalf("valid challenge: %d", code)
	}
	// Existing response uniformity: an unknown tenant with a valid challenge is still 202.
	if code := post(`{"email":"a@example.com","tenant":"nope","code_challenge":"` + good + `"}`); code != http.StatusAccepted {
		t.Fatalf("unknown tenant: %d", code)
	}
}

func TestExchangeRequiresCodeVerifierField(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	h := exchangeHandler(secret, 0)
	rec := postExchange(h, &[]string{secret}[0], `{"code":"x","redirect_origin":"https://app.example.com"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_CODE") {
		t.Fatalf("missing verifier: %d %s", rec.Code, rec.Body.String())
	}
}

// F8
func TestClientIPTrustsForwardedForOnlyFromConfiguredProxies(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cfg := &apptypes.AppConfig{}
	if got := clientIP(mk("172.18.0.2:5000", "203.0.113.9"), cfg); got != "172.18.0.2" {
		t.Fatalf("default must ignore XFF, got %q", got)
	}
	if got := clientIP(mk("172.18.0.2:5000", "203.0.113.9"), nil); got != "172.18.0.2" {
		t.Fatalf("nil cfg must ignore XFF, got %q", got)
	}
	cfg.Security.TrustedProxyCIDRs = []string{"172.18.0.0/16"}
	if got := clientIP(mk("172.18.0.2:5000", "203.0.113.9"), cfg); got != "203.0.113.9" {
		t.Fatalf("behind the trusted proxy the client is the XFF hop, got %q", got)
	}
	if got := clientIP(mk("198.51.100.1:5000", "203.0.113.9"), cfg); got != "198.51.100.1" {
		t.Fatalf("a direct caller cannot spoof XFF, got %q", got)
	}
	if got := clientIP(mk("172.18.0.2:5000", "6.6.6.6, 203.0.113.9"), cfg); got != "203.0.113.9" {
		t.Fatalf("a spoofed left hop must not win, got %q", got)
	}
}
