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
