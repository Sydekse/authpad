package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/idp"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type fakeMLStore struct {
	mu   sync.Mutex
	rows []*auth_repo.MagicLinkToken
}

func (f *fakeMLStore) Create(_ context.Context, t *auth_repo.MagicLinkToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, t)
	return nil
}

func (f *fakeMLStore) Consume(context.Context, string, *uuid.UUID) (*auth_repo.MagicLinkToken, error) {
	panic("Consume must not be reached in these tests")
}

type fakeTenants struct{ orgs map[string]*idp.Organization }

func (f fakeTenants) ResolveTenant(_ context.Context, tenant string) (*idp.Organization, error) {
	return f.orgs[strings.ToLower(strings.TrimSpace(tenant))], nil
}

type sentMail struct{ to, link string }

type fakeMLMailer struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

func (f *fakeMLMailer) SendMagicLink(_ context.Context, to, link string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMail{to, link})
	return f.err
}

type mlFixture struct {
	svc    *MagicLinkService
	store  *fakeMLStore
	mailer *fakeMLMailer
	org    *idp.Organization
	cfg    *apptypes.AppConfig
}

func newMLFixture(t *testing.T) *mlFixture {
	t.Helper()
	org := &idp.Organization{ID: uuid.New(), Slug: "acme", Name: "Acme"}
	cfg := &apptypes.AppConfig{
		APIBasePath: "/api/v1",
		MagicLink: apptypes.MagicLinkConfig{
			Enabled:           true,
			BaseURL:           "https://api.example.com",
			RedirectAllowlist: []string{"https://app.example.com"},
			TTL:               15 * time.Minute,
			EmailLimit:        5,
			IPLimit:           20,
			LimitWindow:       15 * time.Minute,
		},
	}
	f := &mlFixture{store: &fakeMLStore{}, mailer: &fakeMLMailer{}, org: org, cfg: cfg}
	f.svc = NewMagicLinkService(cfg, f.store, fakeTenants{orgs: map[string]*idp.Organization{"acme": org, org.ID.String(): org}},
		f.mailer, security.NewMemoryWindowLimiter(), nil, nil)
	return f
}

func (f *mlFixture) request(email, tenant, redirect, ip string) {
	f.svc.Submit(MagicLinkRequest{Email: email, Tenant: tenant, RedirectTo: redirect, IP: ip})
	f.svc.Wait()
}

func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("no token in %q", link)
	}
	return tok
}

func TestMagicLinkStoresOnlyHashedNormalizedToken(t *testing.T) {
	f := newMLFixture(t)
	f.request("  Alice@Example.COM ", "ACME", "https://app.example.com/home", "1.1.1.1")

	if len(f.mailer.sent) != 1 || len(f.store.rows) != 1 {
		t.Fatalf("want 1 mail and 1 row, got %d / %d", len(f.mailer.sent), len(f.store.rows))
	}
	mail, row := f.mailer.sent[0], f.store.rows[0]
	if mail.to != "alice@example.com" || row.Email != "alice@example.com" {
		t.Fatalf("email not normalized: %q / %q", mail.to, row.Email)
	}
	if !strings.HasPrefix(mail.link, "https://api.example.com/api/v1/magic-link/verify?") {
		t.Fatalf("unexpected link %q", mail.link)
	}
	tok := tokenFromLink(t, mail.link)
	if len(tok) < 43 { // 32 bytes base64url
		t.Fatalf("token too short: %d", len(tok))
	}
	if row.TokenHash != security.HashToken(tok) || row.TokenHash == tok {
		t.Fatal("row must hold the SHA-256 hash, not the token")
	}
	blob, _ := json.Marshal(row)
	if bytes.Contains(blob, []byte(tok)) {
		t.Fatal("raw token present in stored row")
	}
	if row.OrganizationID != f.org.ID {
		t.Fatal("wrong organization")
	}
	if row.RedirectTo != "https://app.example.com/home" {
		t.Fatalf("allowed redirect should be kept, got %q", row.RedirectTo)
	}
	if d := row.ExpiresAt.Sub(row.CreatedAt); d != 15*time.Minute {
		t.Fatalf("expiry = %v, want 15m", d)
	}
	if got := mustQuery(t, mail.link, "tenant"); got != "acme" {
		t.Fatalf("tenant param = %q", got)
	}
}

func mustQuery(t *testing.T, link, key string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func TestMagicLinkTokensAreUnique(t *testing.T) {
	f := newMLFixture(t)
	f.cfg.MagicLink.EmailLimit = 0
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		f.request("a@example.com", "acme", "", "1.1.1.1")
	}
	for _, m := range f.mailer.sent {
		tok := tokenFromLink(t, m.link)
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
	if len(seen) != 20 {
		t.Fatalf("got %d tokens", len(seen))
	}
}

func TestMagicLinkSilentlyDropsBadInput(t *testing.T) {
	f := newMLFixture(t)
	f.request("a@example.com", "no-such-org", "", "1.1.1.1")
	f.request("not-an-email", "acme", "", "1.1.1.1")
	f.request("Bob <b@example.com>", "acme", "", "1.1.1.1")
	f.request("a@example.com", "", "", "1.1.1.1")
	if len(f.mailer.sent)+len(f.store.rows) != 0 {
		t.Fatal("nothing should be stored or sent")
	}
}

func TestMagicLinkInvalidRedirectStoredEmpty(t *testing.T) {
	for _, bad := range []string{"https://evil.test/", "//evil.test", "javascript:alert(1)", "https://app.example.com@evil.test/", "/\\evil.test"} {
		f := newMLFixture(t)
		f.request("a@example.com", "acme", bad, "1.1.1.1")
		if len(f.store.rows) != 1 || f.store.rows[0].RedirectTo != "" {
			t.Fatalf("redirect %q should be dropped silently (row still created)", bad)
		}
	}
}

func TestMagicLinkRateLimitPerEmail(t *testing.T) {
	f := newMLFixture(t)
	f.cfg.MagicLink.IPLimit = 0
	for i := 0; i < 8; i++ {
		f.request("Same@Example.com", "acme", "", "9.9.9.9")
	}
	if len(f.mailer.sent) != 5 || len(f.store.rows) != 5 {
		t.Fatalf("want 5 sends, got %d mails %d rows", len(f.mailer.sent), len(f.store.rows))
	}
	f.request("other@example.com", "acme", "", "9.9.9.9")
	if len(f.mailer.sent) != 6 {
		t.Fatal("other email must not be limited")
	}
	// Case/space variants share the normalized key.
	f.request(" SAME@example.com", "acme", "", "9.9.9.9")
	if len(f.mailer.sent) != 6 {
		t.Fatal("normalized variant must share the limit")
	}
}

func TestMagicLinkRateLimitPerIP(t *testing.T) {
	f := newMLFixture(t)
	f.cfg.MagicLink.EmailLimit = 0
	for i := 0; i < 25; i++ {
		f.request("user"+string(rune('a'+i))+"@example.com", "acme", "", "7.7.7.7")
	}
	if len(f.mailer.sent) != 20 {
		t.Fatalf("want 20 sends, got %d", len(f.mailer.sent))
	}
	f.request("fresh@example.com", "acme", "", "8.8.8.8")
	if len(f.mailer.sent) != 21 {
		t.Fatal("other IP must not be limited")
	}
}

func TestMagicLinkMailerErrorIsSwallowed(t *testing.T) {
	f := newMLFixture(t)
	f.mailer.err = io.ErrUnexpectedEOF
	f.request("a@example.com", "acme", "", "1.1.1.1") // must not panic
	if len(f.store.rows) != 1 {
		t.Fatal("row should still be stored")
	}
}

func TestMagicLinkVerifyRejectsWithoutTouchingStore(t *testing.T) {
	f := newMLFixture(t)
	for _, tc := range []struct{ token, tenant string }{
		{"", ""},
		{strings.Repeat("a", 500), ""},
		{"sometoken", "unknown-tenant"},
	} {
		if _, err := f.svc.Verify(context.Background(), tc.token, tc.tenant, "", ""); err != ErrMagicLinkInvalid {
			t.Fatalf("Verify(%q,%q) = %v", tc.token, tc.tenant, err)
		}
	}
}

func TestDevMagicLinkMailerPrintsLink(t *testing.T) {
	var buf bytes.Buffer
	cfg := &apptypes.AppConfig{Env: "development"}
	m := NewMagicLinkMailer(cfg)
	dev, ok := m.(*DevMagicLinkMailer)
	if !ok {
		t.Fatalf("dev without key should use DevMagicLinkMailer, got %T", m)
	}
	dev.Out = &buf
	if err := dev.SendMagicLink(context.Background(), "a@example.com", "https://x/verify?token=SECRET"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "token=SECRET") {
		t.Fatalf("dev mailer should print the link, got %q", buf.String())
	}
}

func TestProductionWithoutKeyNeverPrintsToken(t *testing.T) {
	cfg := &apptypes.AppConfig{Env: "production"}
	m := NewMagicLinkMailer(cfg)
	if _, ok := m.(*DevMagicLinkMailer); ok {
		t.Fatal("production must not use the dev mailer")
	}
	// Capture stdout/stderr-ish output via the writer-less path: the mailer
	// must fail without echoing the link anywhere, including the error.
	err := m.SendMagicLink(context.Background(), "a@example.com", "https://x/verify?token=SECRET")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatal("error must not contain the token")
	}
}

func TestProductionWithoutKeyLogsNoToken(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = prev }()

	f := newMLFixture(t)
	f.cfg.Env = "production"
	f.svc.mailer = NewMagicLinkMailer(f.cfg) // no key, no override
	f.request("a@example.com", "acme", "", "1.1.1.1")

	if len(f.store.rows) != 1 {
		t.Fatal("token should still be stored")
	}
	out := logs.String()
	if out == "" {
		t.Fatal("expected an error log for the unsent link")
	}
	for _, leak := range []string{"token=", "magic-link/verify", "a@example.com"} {
		if strings.Contains(out, leak) {
			t.Fatalf("production log leaks %q: %s", leak, out)
		}
	}
}

func TestMagicLinkConfigValidation(t *testing.T) {
	base := func() apptypes.AppConfig {
		return apptypes.AppConfig{
			AuthDatabaseURL: "postgres://x", IdPDatabaseURL: "postgres://x", Env: "development",
			Tenancy:   apptypes.TenancyConfig{Enabled: true},
			MagicLink: apptypes.MagicLinkConfig{Enabled: true, BaseURL: "https://api.example.com"},
		}
	}
	c := base()
	if err := c.Validate(); err != nil {
		t.Fatalf("dev config should be valid: %v", err)
	}
	c = base()
	c.MagicLink.BaseURL = ""
	if c.Validate() == nil {
		t.Fatal("missing BaseURL must fail")
	}
	c = base()
	c.Tenancy.Enabled = false
	if c.Validate() == nil {
		t.Fatal("magic link without tenancy must fail")
	}
	c = base()
	c.Env = "production"
	c.Security.SessionSecret = strings.Repeat("s", 32)
	c.Pages.SignInURL = "https://app.example.com/sign-in"
	if c.Validate() == nil {
		t.Fatal("production without RESEND_API_KEY must refuse to start")
	}
	c.Email.ResendAPIKey = "re_123"
	if err := c.Validate(); err != nil {
		t.Fatalf("production with key should pass: %v", err)
	}

	c = base()
	c.MagicLink.CodeFlow = true
	if c.Validate() == nil {
		t.Fatal("code flow without exchange secret must fail")
	}
	c.MagicLink.ExchangeSecret = "short"
	if err := c.Validate(); err != nil {
		t.Fatalf("dev code flow with a secret should pass: %v", err)
	}
	c.Env = "production"
	c.Security.SessionSecret = strings.Repeat("s", 32)
	c.Pages.SignInURL = "https://app.example.com/sign-in"
	c.Email.ResendAPIKey = "re_123"
	if c.Validate() == nil {
		t.Fatal("short exchange secret must fail in production")
	}
	c.MagicLink.ExchangeSecret = strings.Repeat("x", 32)
	if err := c.Validate(); err != nil {
		t.Fatalf("production code flow with long secret should pass: %v", err)
	}
}

func TestResendMagicLinkMailerRequest(t *testing.T) {
	var gotAuth, gotCT, gotMethod string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotCT, gotMethod = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Method
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	m := &ResendMagicLinkMailer{APIKey: "re_key", From: "Auth <no-reply@example.com>", AppName: "Acme", Endpoint: srv.URL}
	if err := m.SendMagicLink(context.Background(), "a@example.com", "https://api.example.com/verify?token=abc"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotAuth != "Bearer re_key" || gotCT != "application/json" {
		t.Fatalf("bad request: %s %q %q", gotMethod, gotAuth, gotCT)
	}
	if body["from"] != "Auth <no-reply@example.com>" || body["to"].([]any)[0] != "a@example.com" {
		t.Fatalf("bad payload: %v", body)
	}
	if !strings.Contains(body["text"].(string), "token=abc") {
		t.Fatal("link missing from text body")
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(422) }))
	defer fail.Close()
	m.Endpoint = fail.URL
	if err := m.SendMagicLink(context.Background(), "a@example.com", "https://x?token=abc"); err == nil || strings.Contains(err.Error(), "abc") {
		t.Fatalf("expected token-free error, got %v", err)
	}
}
