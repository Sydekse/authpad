package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestInviteCallbackURL(t *testing.T) {
	cfg := &apptypes.AppConfig{AllowedOrigins: []string{"https://app.example.com/"}}
	cfg.MagicLink.RedirectAllowlist = []string{"https://Staging.Example.com"}
	cfg.Pages.SignUpURL = "https://pages.example.com/sign-up"
	for raw, want := range map[string]bool{
		"":                                       true,
		"https://app.example.com/invite/accept/": true,
		"https://staging.example.com/invite":     true,
		"https://pages.example.com/x?y=1":        true,
		"https://evil.example.net/invite":        false,
		"http://app.example.com/invite":          false,
		"javascript:alert(1)":                    false,
		"data:text/html,hi":                      false,
		"https://app.example.com@evil.test/":     false,
		"https://user:pw@app.example.com/":       false,
		"//app.example.com/invite":               false,
		"/invite/accept":                         false,
		"https://app.example.com/invite#x":       false,
	} {
		if _, ok := inviteCallbackURL(raw, cfg); ok != want {
			t.Errorf("%q: ok=%v want %v", raw, ok, want)
		}
	}
	if got, _ := inviteCallbackURL("https://app.example.com/invite/accept/", cfg); got != "https://app.example.com/invite/accept" {
		t.Fatalf("trailing slash kept: %q", got)
	}
	explicit := &apptypes.AppConfig{AllowedOrigins: []string{"https://app.example.com"}}
	explicit.Invitations.CallbackOrigins = []string{"https://only.example.com"}
	if _, ok := inviteCallbackURL("https://app.example.com/x", explicit); ok {
		t.Fatal("CallbackOrigins must replace the fallback list")
	}
	if _, ok := inviteCallbackURL("https://only.example.com/x", explicit); !ok {
		t.Fatal("CallbackOrigins origin refused")
	}
}

func TestTokenParamDecodesPercentEncoding(t *testing.T) {
	r := chi.NewRouter()
	var got string
	r.Get("/i/{token}/validate", func(w http.ResponseWriter, req *http.Request) { got = tokenParam(req) })
	for path, want := range map[string]string{"/i/abc%3D/validate": "abc=", "/i/abc=/validate": "abc=", "/i/a-b_c/validate": "a-b_c"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		if got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
	}
}

type plainMailer struct {
	invites int
	err     error
}

func (m *plainMailer) SendPasswordReset(string, string) error     { return nil }
func (m *plainMailer) SendEmailVerification(string, string) error { return nil }
func (m *plainMailer) SendInvitation(string, string, string) error {
	m.invites++
	return m.err
}

func TestSendOrgInvitationFallsBackToPlainMailer(t *testing.T) {
	m := &plainMailer{}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	sendOrgInvitation(req, m, nil, "acme", uuid.New(), "a@x.test", "https://x.test/?token=a%3D", "member", time.Now())
	if m.invites != 1 {
		t.Fatalf("plain mailer used %d times", m.invites)
	}
	m.err = errors.New("resend down")
	sendOrgInvitation(req, m, nil, "acme", uuid.New(), "a@x.test", "https://x.test/?token=a%3D", "member", time.Now())
	if m.invites != 2 {
		t.Fatal("a failed send must still be attempted once")
	}
}
