package service

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
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

func newCodeSvc() (*MagicLinkService, *fakeCodeStore) {
	st := newFakeCodeStore()
	svc := NewMagicLinkService(&apptypes.AppConfig{}, nil, nil, nil, security.NewMemoryWindowLimiter(), nil, nil)
	svc.codes = st
	return svc, st
}

func TestCreateCodeStoresOnlyHashBoundToOrigin(t *testing.T) {
	svc, st := newCodeSvc()
	sid, oid := uuid.New(), uuid.New()
	code, err := svc.CreateCode(context.Background(), sid, oid, "https://App.Example.com/talks/1?x=1")
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
	if rec.SessionID != sid || rec.OrganizationID != oid || rec.RedirectOrigin != "https://app.example.com:443" {
		t.Fatalf("bad binding: %+v", rec)
	}
	if d := rec.ExpiresAt.Sub(rec.CreatedAt); d != 60*time.Second {
		t.Fatalf("ttl = %v, want 60s", d)
	}
	if len(code) < 43 { // 32 bytes base64
		t.Fatalf("code too short: %d", len(code))
	}
	if _, err := svc.CreateCode(context.Background(), sid, oid, "javascript:alert(1)"); err == nil {
		t.Fatal("non-http redirect must be refused")
	}
}

func TestExchangeRejectsBeforeTouchingSession(t *testing.T) {
	svc, st := newCodeSvc()
	ctx := context.Background()
	issue := func() string {
		c, err := svc.CreateCode(ctx, uuid.New(), uuid.New(), "https://app.example.com/")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Unknown code, empty code, oversized code.
	for _, c := range []string{"", "nope", strings.Repeat("a", 500)} {
		if _, err := svc.Exchange(ctx, c, "https://app.example.com"); err != ErrMagicCodeInvalid {
			t.Fatalf("code %q: %v", c, err)
		}
	}

	// Wrong origin (several shapes), and the code is burned afterwards.
	for _, bad := range []string{"https://evil.test", "http://app.example.com", "https://app.example.com:8443", "https://app.example.com.evil.test", "", "https://app.example.com/path"} {
		c := issue()
		if _, err := svc.Exchange(ctx, c, bad); err != ErrMagicCodeInvalid {
			t.Fatalf("origin %q accepted: %v", bad, err)
		}
		if rec, _ := st.Consume(ctx, security.HashToken(c)); rec != nil {
			t.Fatalf("origin %q: code should be burned", bad)
		}
	}

	// Expired.
	c := issue()
	st.rows[security.HashToken(c)].ExpiresAt = time.Now().Add(-time.Second)
	if _, err := svc.Exchange(ctx, c, "https://app.example.com"); err != ErrMagicCodeInvalid {
		t.Fatalf("expired code: %v", err)
	}

	// Reuse: a consumed code never works again.
	c = issue()
	if rec, _ := st.Consume(ctx, security.HashToken(c)); rec == nil {
		t.Fatal("first consume should succeed")
	}
	if _, err := svc.Exchange(ctx, c, "https://app.example.com"); err != ErrMagicCodeInvalid {
		t.Fatalf("reused code: %v", err)
	}
}
