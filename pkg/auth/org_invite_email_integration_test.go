package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Sydekse/authpad/pkg/auth"
	"github.com/google/uuid"
)

// orgInviteMailer captures organization invites; it implements both Mailer and
// the optional OrgInvitationMailer.
type orgInviteMailer struct {
	org   []auth.OrgInvitationEmail
	plain int
}

func (m *orgInviteMailer) SendPasswordReset(string, string) error     { return nil }
func (m *orgInviteMailer) SendEmailVerification(string, string) error { return nil }
func (m *orgInviteMailer) SendInvitation(string, string, string) error {
	m.plain++
	return nil
}
func (m *orgInviteMailer) SendOrgInvitation(msg auth.OrgInvitationEmail) error {
	m.org = append(m.org, msg)
	return nil
}

// Opaque tokens are padded URL-safe base64, so they end in "=". A link or API
// client may percent-encode that as %3D; the invite must still validate.
func TestOrgInviteEmailNamesOrgAndTokenSurvivesEncoding(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := auth.MigrateWithOptions(ctx, dsn, dsn, auth.MigrationOptions{AuthTable: "schema_migrations_auth", IdPTable: "schema_migrations_idp"}); err != nil {
		t.Fatal(err)
	}
	mail := &orgInviteMailer{}
	cfg := auth.DefaultConfig()
	cfg.AuthDatabaseURL, cfg.IdPDatabaseURL = dsn, dsn
	cfg.Security.RateLimitRPM = 0
	cfg.Security.CSRFEnabled = false
	cfg.Security.SessionSecret = "integration-test-session-secret-32chars"
	cfg.Tenancy.Enabled = true
	cfg.Mailer = mail
	cfg.AllowedOrigins = []string{"https://app.example.com"}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	h := mounted(a)

	owner, err := a.CreateAccount(ctx, auth.CreateAccountRequest{Email: fmt.Sprintf("owner-%s@example.com", uuid.NewString()), Password: "password1", Profile: map[string]any{"name": "Owner"}}, "127.0.0.1", "t")
	if err != nil || owner.Token == "" {
		t.Fatalf("owner account: %v", err)
	}
	slug := "inv-" + uuid.NewString()[:8]
	if _, err := a.CreateOrganization(ctx, owner.UserID, "Kestrel Labs", slug, nil); err != nil {
		t.Fatal(err)
	}

	invite := func(email, callback string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"email":%q,"role":"admin","callback_url":%q}`, email, callback)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+slug+"/invitations", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+owner.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, bad := range []string{"https://evil.example.net/invite", "javascript:alert(1)"} {
		if rec := invite("victim@example.com", bad); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_CALLBACK_URL") {
			t.Fatalf("callback %q: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
	if len(mail.org) != 0 || mail.plain != 0 {
		t.Fatal("a refused callback must not send email")
	}

	invitee := fmt.Sprintf("boss-%s@example.com", uuid.NewString())
	rec := invite(invitee, "https://app.example.com/invite/accept")
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !strings.HasSuffix(created.Token, "=") {
		t.Fatalf("expected padded token, got length %d", len(created.Token))
	}

	if mail.plain != 0 || len(mail.org) != 1 {
		t.Fatalf("want one org invitation email, got org=%d plain=%d", len(mail.org), mail.plain)
	}
	msg := mail.org[0]
	if msg.OrgName != "Kestrel Labs" || msg.To != invitee || msg.Role != "admin" || msg.ExpiresAt.IsZero() {
		t.Fatalf("unexpected email: org=%q to=%q role=%q", msg.OrgName, msg.To, msg.Role)
	}
	link, err := url.Parse(msg.InviteURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(link.RawQuery, "%3D") {
		t.Fatal("token padding must be percent-encoded in the link query")
	}
	if got := link.Query().Get("token"); got != created.Token {
		t.Fatal("link token does not decode to the issued token")
	}

	for name, seg := range map[string]string{"raw": created.Token, "escaped": url.PathEscape(created.Token), "query-escaped": url.QueryEscape(created.Token)} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/invitations/"+seg+"/validate", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out struct {
			Valid bool `json:"valid"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusOK || !out.Valid {
			t.Fatalf("%s token segment: status %d valid=%v", name, rec.Code, out.Valid)
		}
	}
}
