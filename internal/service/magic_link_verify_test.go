package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/auth"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	"github.com/google/uuid"
)

// oneShotStore hands back rec exactly once, like the real atomic consume.
type oneShotStore struct {
	fakeMLStore
	rec  *auth_repo.MagicLinkToken
	used bool
}

func (s *oneShotStore) Consume(context.Context, string, *uuid.UUID) (*auth_repo.MagicLinkToken, error) {
	if s.used {
		return nil, nil
	}
	s.used = true
	return s.rec, nil
}

type fakeAccounts struct {
	user    *auth.UserAuth
	created bool
	staff   bool
	hasPw   bool

	staffErr, pwErr, takeErr error

	takeOvers int
	checks    int
}

func (f *fakeAccounts) FindOrCreate(context.Context, string, string, string) (*auth.UserAuth, bool, error) {
	return f.user, f.created, nil
}
func (f *fakeAccounts) IsStaff(context.Context, uuid.UUID) (bool, error) {
	f.checks++
	return f.staff, f.staffErr
}
func (f *fakeAccounts) HasPassword(context.Context, uuid.UUID) (bool, error) {
	f.checks++
	return f.hasPw, f.pwErr
}
func (f *fakeAccounts) TakeOver(context.Context, uuid.UUID) error {
	f.takeOvers++
	return f.takeErr
}

func verifyFixture(t *testing.T, acct *fakeAccounts) *mlFixture {
	t.Helper()
	f := newMLFixture(t)
	f.svc.store = &oneShotStore{rec: &auth_repo.MagicLinkToken{
		ID: uuid.New(), OrganizationID: f.org.ID, Email: "victim@example.com",
		CodeChallenge: testChallenge, ExpiresAt: time.Now().Add(time.Minute),
	}}
	f.svc.SetAccounts(acct)
	return f
}

func activeUser(verified bool) *auth.UserAuth {
	return &auth.UserAuth{ID: uuid.New(), Email: "victim@example.com", Status: "active", EmailVerified: verified}
}

// F1: an unverified account may hold credentials its earlier registrant chose.
func TestVerifyUnverifiedAccountIsTakenOver(t *testing.T) {
	acct := &fakeAccounts{user: activeUser(false), hasPw: true}
	f := verifyFixture(t, acct)
	f.cfg.MagicLink.AllowPasswordAccounts = true // otherwise the password account is refused outright

	res, err := f.svc.Verify(context.Background(), "tok", "", "1.1.1.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if acct.takeOvers != 1 {
		t.Fatalf("TakeOver called %d times, want 1", acct.takeOvers)
	}
	if !res.User.EmailVerified {
		t.Fatal("account should be verified after takeover")
	}
	if res.CodeChallenge != testChallenge {
		t.Fatal("verified result must carry the PKCE challenge")
	}
}

func TestVerifyTakeOverFailureRejects(t *testing.T) {
	acct := &fakeAccounts{user: activeUser(false), takeErr: errors.New("db")}
	f := verifyFixture(t, acct)
	if _, err := f.svc.Verify(context.Background(), "tok", "", "", ""); err != ErrMagicLinkInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyVerifiedAndNewAccountsAreNotTakenOver(t *testing.T) {
	for name, acct := range map[string]*fakeAccounts{
		"verified existing": {user: activeUser(true)},
		"new":               {user: activeUser(true), created: true, staff: true, hasPw: true}, // checks skipped for a fresh account
	} {
		f := verifyFixture(t, acct)
		if _, err := f.svc.Verify(context.Background(), "tok", "", "", ""); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if acct.takeOvers != 0 {
			t.Fatalf("%s: must not be taken over", name)
		}
	}
}

// F2: staff/admin accounts and password accounts are refused with the generic error.
func TestVerifyRefusesStaffAndPasswordAccounts(t *testing.T) {
	for name, tc := range map[string]struct {
		acct  fakeAccounts
		allow bool
		ok    bool
	}{
		"staff":                               {acct: fakeAccounts{staff: true}},
		"staff even when allowed":             {acct: fakeAccounts{staff: true, hasPw: true}, allow: true},
		"password account":                    {acct: fakeAccounts{hasPw: true}},
		"password account, allowed":           {acct: fakeAccounts{hasPw: true}, allow: true, ok: true},
		"passwordless attendee":               {acct: fakeAccounts{}, ok: true},
		"staff lookup fails closed":           {acct: fakeAccounts{staffErr: errors.New("db")}, allow: true},
		"credential lookup fails":             {acct: fakeAccounts{pwErr: errors.New("db")}},
		"credential error ignored if allowed": {acct: fakeAccounts{pwErr: errors.New("db")}, allow: true, ok: true},
	} {
		acct := tc.acct
		acct.user = activeUser(true)
		f := verifyFixture(t, &acct)
		f.cfg.MagicLink.AllowPasswordAccounts = tc.allow
		_, err := f.svc.Verify(context.Background(), "tok", "", "", "")
		if tc.ok && err != nil {
			t.Fatalf("%s: unexpected %v", name, err)
		}
		if !tc.ok && err != ErrMagicLinkInvalid {
			t.Fatalf("%s: got %v, want the uniform ErrMagicLinkInvalid", name, err)
		}
	}
}

func TestVerifyInactiveAccountRejected(t *testing.T) {
	u := activeUser(true)
	u.Status = "locked"
	f := verifyFixture(t, &fakeAccounts{user: u})
	if _, err := f.svc.Verify(context.Background(), "tok", "", "", ""); err != ErrMagicLinkInvalid {
		t.Fatalf("got %v", err)
	}
}

// F4: the challenge is stored with the token only in code-flow mode, and a
// code-flow link is never minted without a valid one.
func TestMagicLinkRequestBindsPKCEChallenge(t *testing.T) {
	f := newMLFixture(t)
	f.cfg.MagicLink.CodeFlow = true
	f.svc.Submit(MagicLinkRequest{Email: "a@example.com", Tenant: "acme", IP: "1.1.1.1", CodeChallenge: testChallenge})
	f.svc.Wait()
	if len(f.store.rows) != 1 || f.store.rows[0].CodeChallenge != testChallenge {
		t.Fatalf("challenge not stored with the token: %+v", f.store.rows)
	}
	for _, bad := range []string{"", "not-a-challenge", testVerifier + "x"} {
		f.svc.Submit(MagicLinkRequest{Email: "b@example.com", Tenant: "acme", IP: "1.1.1.1", CodeChallenge: bad})
		f.svc.Wait()
	}
	if len(f.store.rows) != 1 || len(f.mailer.sent) != 1 {
		t.Fatal("no link may be issued without a valid challenge in code-flow mode")
	}

	// Cookie mode ignores any challenge.
	g := newMLFixture(t)
	g.request("a@example.com", "acme", "", "1.1.1.1")
	if len(g.store.rows) != 1 || g.store.rows[0].CodeChallenge != "" {
		t.Fatal("cookie mode must not require or store a challenge")
	}
}

// F12
func TestMailerFallbackOnlyInDevelopment(t *testing.T) {
	for _, env := range []string{"production", "prod", "staging", ""} {
		m := NewMagicLinkMailer(&apptypes.AppConfig{Env: env})
		if _, ok := m.(*DevMagicLinkMailer); ok {
			t.Fatalf("Env %q must not get the dev mailer", env)
		}
		if err := m.SendMagicLink(context.Background(), "a@example.com", "https://x/verify?token=SECRET"); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("Env %q: want a token-free error, got %v", env, err)
		}
	}
	if _, ok := NewMagicLinkMailer(&apptypes.AppConfig{Env: "development"}).(*DevMagicLinkMailer); !ok {
		t.Fatal("development should use the dev mailer")
	}
}

func TestDevMailerRedactsTokenUnlessDevelopment(t *testing.T) {
	var buf bytes.Buffer
	m := &DevMagicLinkMailer{Out: &buf} // zero value: as if built outside development
	if err := m.SendMagicLink(context.Background(), "a@example.com", "https://x/api/v1/magic-link/verify?tenant=acme&token=SECRET"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "SECRET") || !strings.Contains(out, "token=REDACTED") || !strings.Contains(out, "tenant=acme") {
		t.Fatalf("token not redacted: %q", out)
	}
}

// F13
type fakePurger struct {
	fakeMLStore
	mu    sync.Mutex
	calls int
	last  time.Time
}

func (p *fakePurger) DeleteExpired(_ context.Context, before time.Time) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.last = before
	return 0, nil
}

func (p *fakePurger) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestCleanupPurgesPeriodicallyAndStops(t *testing.T) {
	f := newMLFixture(t)
	p := &fakePurger{}
	f.svc.store = p
	ctx, cancel := context.WithCancel(context.Background())
	done := f.svc.StartCleanup(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for p.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.count() < 3 {
		t.Fatalf("expected an immediate purge plus ticks, got %d", p.count())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup goroutine did not stop")
	}
	n := p.count()
	time.Sleep(40 * time.Millisecond)
	if p.count() != n {
		t.Fatal("purge kept running after cancel")
	}
	if p.last.After(time.Now()) {
		t.Fatal("cutoff must not be in the future")
	}
}
