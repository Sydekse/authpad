package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
