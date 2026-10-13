package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/idp"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
)

// fakeCodeStore mirrors the repo's atomic consume under a mutex.
type fakeCodeStore struct {
	mu   sync.Mutex
	rows map[string]*auth_repo.MagicLinkCode
	used map[string]bool
}

func newFakeCodeStore() *fakeCodeStore {
	return &fakeCodeStore{rows: map[string]*auth_repo.MagicLinkCode{}, used: map[string]bool{}}
}

func (f *fakeCodeStore) Create(_ context.Context, c *auth_repo.MagicLinkCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[c.CodeHash] = c
	return nil
}

func (f *fakeCodeStore) Consume(_ context.Context, hash string) (*auth_repo.MagicLinkCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.rows[hash]
	if c == nil || f.used[hash] || !c.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	f.used[hash] = true
	return c, nil
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B

var testChallenge = PKCEChallenge(testVerifier)

func newCodeSvc() (*MagicLinkService, *fakeCodeStore) {
	st := newFakeCodeStore()
	svc := NewMagicLinkService(&apptypes.AppConfig{}, nil, nil, nil, security.NewMemoryWindowLimiter(), nil, nil)
	svc.codes = st
	return svc, st
}

func TestCreateCodeStoresOnlyHashBoundToOrigin(t *testing.T) {
	svc, st := newCodeSvc()
	sid, oid := uuid.New(), uuid.New()
	code, err := svc.CreateCode(context.Background(), sid, oid, "https://App.Example.com/talks/1?x=1", testChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, raw := st.rows[code]; raw {
		t.Fatal("raw code stored")
	}
	rec := st.rows[security.HashToken(code)]
	if rec == nil {
		t.Fatal("hash not stored")
	}
	if rec.CodeChallenge != testChallenge {
		t.Fatal("PKCE challenge must be copied to the code")
	}
	if rec.SessionID != sid || rec.OrganizationID != oid || rec.RedirectOrigin != "https://app.example.com:443" {
		t.Fatalf("bad binding: %+v", rec)
	}
	if d := rec.ExpiresAt.Sub(rec.CreatedAt); d != 60*time.Second {
		t.Fatalf("ttl = %v, want 60s", d)
	}
	if len(code) < 43 { // 32 bytes base64
		t.Fatalf("code too short: %d", len(code))
	}
	if _, err := svc.CreateCode(context.Background(), sid, oid, "javascript:alert(1)", testChallenge); err == nil {
		t.Fatal("non-http redirect must be refused")
	}
}

func TestExchangeRejectsBeforeTouchingSession(t *testing.T) {
	svc, st := newCodeSvc()
	ctx := context.Background()
	issue := func() string {
		c, err := svc.CreateCode(ctx, uuid.New(), uuid.New(), "https://app.example.com/", testChallenge)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Unknown code, empty code, oversized code.
	for _, c := range []string{"", "nope", strings.Repeat("a", 500)} {
		if _, err := svc.Exchange(ctx, c, "https://app.example.com", testVerifier); err != ErrMagicCodeInvalid {
			t.Fatalf("code %q: %v", c, err)
		}
	}

	// Wrong origin (several shapes), and the code is burned afterwards.
	for _, bad := range []string{"https://evil.test", "http://app.example.com", "https://app.example.com:8443", "https://app.example.com.evil.test", "", "https://app.example.com/path"} {
		c := issue()
		if _, err := svc.Exchange(ctx, c, bad, testVerifier); err != ErrMagicCodeInvalid {
			t.Fatalf("origin %q accepted: %v", bad, err)
		}
		if rec, _ := st.Consume(ctx, security.HashToken(c)); rec != nil {
			t.Fatalf("origin %q: code should be burned", bad)
		}
	}

	// Expired.
	c := issue()
	st.rows[security.HashToken(c)].ExpiresAt = time.Now().Add(-time.Second)
	if _, err := svc.Exchange(ctx, c, "https://app.example.com", testVerifier); err != ErrMagicCodeInvalid {
		t.Fatalf("expired code: %v", err)
	}

	// Reuse: a consumed code never works again.
	c = issue()
	if rec, _ := st.Consume(ctx, security.HashToken(c)); rec == nil {
		t.Fatal("first consume should succeed")
	}
	if _, err := svc.Exchange(ctx, c, "https://app.example.com", testVerifier); err != ErrMagicCodeInvalid {
		t.Fatalf("reused code: %v", err)
	}
}

func TestPKCEChallengeMatchesRFC7636Vector(t *testing.T) {
	if got := PKCEChallenge(testVerifier); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge = %q", got)
	}
	if !ValidCodeChallenge(PKCEChallenge(testVerifier)) {
		t.Fatal("derived challenge must validate")
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 44), strings.Repeat("a", 42) + "=", strings.Repeat("a", 42) + "+"} {
		if ValidCodeChallenge(bad) {
			t.Fatalf("%q must not validate", bad)
		}
	}
}

func TestCreateCodeRequiresChallenge(t *testing.T) {
	svc, st := newCodeSvc()
	for _, bad := range []string{"", "plain-verifier-not-hashed"} {
		if _, err := svc.CreateCode(context.Background(), uuid.New(), uuid.New(), "https://app.example.com/", bad); err == nil {
			t.Fatalf("challenge %q accepted", bad)
		}
	}
	if len(st.rows) != 0 {
		t.Fatal("no code may be stored without a valid challenge")
	}
}

// The verifier is checked before any session is touched (authSvc is nil here, so
// reaching it would panic), and a wrong or missing verifier burns the code.
func TestExchangeRequiresMatchingVerifier(t *testing.T) {
	svc, st := newCodeSvc()
	ctx := context.Background()
	other := "A" + testVerifier[1:]
	for name, verifier := range map[string]string{"wrong": other, "missing": "", "short": "abc", "bad charset": strings.Repeat("!", 43), "challenge as verifier": testChallenge + "x"} {
		c, err := svc.CreateCode(ctx, uuid.New(), uuid.New(), "https://app.example.com/", testChallenge)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Exchange(ctx, c, "https://app.example.com", verifier); err != ErrMagicCodeInvalid {
			t.Fatalf("%s verifier accepted: %v", name, err)
		}
		if name == "wrong" || name == "challenge as verifier" {
			if rec, _ := st.Consume(ctx, security.HashToken(c)); rec != nil {
				t.Fatalf("%s: a mismatching verifier should burn the code", name)
			}
		}
	}
	// A legacy row with no stored challenge can never be exchanged.
	c, _ := svc.CreateCode(ctx, uuid.New(), uuid.New(), "https://app.example.com/", testChallenge)
	st.rows[security.HashToken(c)].CodeChallenge = ""
	if _, err := svc.Exchange(ctx, c, "https://app.example.com", testVerifier); err != ErrMagicCodeInvalid {
		t.Fatalf("challenge-less code accepted: %v", err)
	}
}

type fakeMembers struct {
	m   *idp.OrganizationMembership
	err error
}

func (f fakeMembers) Membership(context.Context, uuid.UUID, uuid.UUID) (*idp.OrganizationMembership, error) {
	return f.m, f.err
}

func TestTenantMembershipOnlyForActiveMembers(t *testing.T) {
	svc, _ := newCodeSvc()
	ctx := context.Background()
	org, user := uuid.New(), uuid.New()

	if id, member, role := svc.tenantMembership(ctx, org, user); id != nil || member || role != "" {
		t.Fatal("without a membership lookup the user is a non-member")
	}
	for name, m := range map[string]fakeMembers{
		"stranger":  {},
		"suspended": {m: &idp.OrganizationMembership{Status: "suspended", Role: "member"}},
		"error":     {err: errors.New("db down")},
	} {
		svc.SetMembership(m)
		if id, member, role := svc.tenantMembership(ctx, org, user); id != nil || member || role != "" {
			t.Fatalf("%s must not get org_id/role: %v %v %q", name, id, member, role)
		}
	}
	svc.SetMembership(fakeMembers{m: &idp.OrganizationMembership{Status: "active", Role: "owner"}})
	id, member, role := svc.tenantMembership(ctx, org, user)
	if id == nil || *id != org || !member || role != "owner" {
		t.Fatalf("active member: %v %v %q", id, member, role)
	}
}
