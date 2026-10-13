package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/domain/auth"
	"github.com/Sydekse/authpad/internal/domain/idp"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ErrMagicLinkInvalid covers every verify failure (unknown, expired, reused,
// wrong tenant, locked account) so callers cannot tell them apart.
var ErrMagicLinkInvalid = errors.New("magic link invalid or expired")

const (
	magicLinkMaxInFlight = 64
	magicLinkJobTimeout  = 20 * time.Second
	magicLinkTokenMaxLen = 256
)

// MagicLinkStore persists token hashes.
type MagicLinkStore interface {
	Create(ctx context.Context, t *auth_repo.MagicLinkToken) error
	Consume(ctx context.Context, tokenHash string, orgID *uuid.UUID) (*auth_repo.MagicLinkToken, error)
}

// TenantResolver maps an org slug or id to an organization (nil when unknown).
type TenantResolver interface {
	ResolveTenant(ctx context.Context, tenant string) (*idp.Organization, error)
}

type MagicLinkRequest struct {
	Email      string
	Tenant     string
	RedirectTo string
	IP         string
	// CodeChallenge is the PKCE S256 challenge; required when the code flow is on.
	CodeChallenge string
}

type MagicLinkVerified struct {
	User          *auth.UserAuth
	Organization  *idp.Organization
	RedirectTo    string // validated against the allowlist; empty means use the default
	CodeChallenge string // carried from the request into the one-time code
	Created       bool
}

// MagicLinkAccounts is how Verify finds, classifies and hardens accounts.
type MagicLinkAccounts interface {
	// FindOrCreate returns the account for email, creating a passwordless one
	// when none exists. A nil user means sign-in is not possible.
	FindOrCreate(ctx context.Context, email, ip, ua string) (user *auth.UserAuth, created bool, err error)
	// IsStaff reports whether the account is a platform admin or org staff.
	IsStaff(ctx context.Context, userID uuid.UUID) (bool, error)
	HasPassword(ctx context.Context, userID uuid.UUID) (bool, error)
	// TakeOver is called when the link is the first proof of inbox ownership for
	// an unverified account. Whoever registered it earlier may have planted
	// credentials, so it revokes every session, removes the password and clears
	// MFA enrolment, then marks the email verified.
	TakeOver(ctx context.Context, userID uuid.UUID) error
}

// MagicLinkService issues and redeems passwordless sign-in links.
type MagicLinkService struct {
	cfg     *apptypes.AppConfig
	store   MagicLinkStore
	tenants TenantResolver
	mailer  apptypes.MagicLinkMailer
	limiter security.WindowLimiter

	// Verify-side dependencies. Nil in request-only unit tests.
	accounts MagicLinkAccounts
	dbAccts  *dbMagicLinkAccounts

	// Code-flow dependencies; set by EnableCodeFlow.
	codes   MagicLinkCodeStore
	authSvc *AuthService
	members MembershipLookup

	sem chan struct{}
	wg  sync.WaitGroup
}

func NewMagicLinkService(
	cfg *apptypes.AppConfig,
	store MagicLinkStore,
	tenants TenantResolver,
	mailer apptypes.MagicLinkMailer,
	limiter security.WindowLimiter,
	users *auth_repo.UserAuthRepo,
	account *AccountService,
) *MagicLinkService {
	s := &MagicLinkService{
		cfg: cfg, store: store, tenants: tenants, mailer: mailer, limiter: limiter,
		sem: make(chan struct{}, magicLinkMaxInFlight),
	}
	if users != nil && account != nil {
		s.dbAccts = &dbMagicLinkAccounts{cfg: cfg, users: users, account: account}
		s.accounts = s.dbAccts
	}
	return s
}

// SetAccounts replaces the account backend (tests, hosts).
func (s *MagicLinkService) SetAccounts(a MagicLinkAccounts) { s.accounts = a }

// WireAccountGuards supplies what the database-backed account backend needs to
// classify staff, detect password credentials and clear an untrusted account.
// Until it is called every verify for an existing account fails closed.
func (s *MagicLinkService) WireAccountGuards(creds *auth_repo.CredentialRepo, factors *auth_repo.FactorRepo, staff StaffFunc) {
	if s.dbAccts != nil {
		s.dbAccts.creds, s.dbAccts.factors, s.dbAccts.staff = creds, factors, staff
	}
}

// ValidCodeChallenge reports whether c is a well-formed PKCE S256 challenge:
// the unpadded base64url encoding of a SHA-256 digest (43 characters).
func ValidCodeChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// Wait blocks until every submitted request has finished (tests, shutdown).
func (s *MagicLinkService) Wait() { s.wg.Wait() }

// Submit queues req and returns immediately, so response timing does not depend
// on whether the email or tenant exists, on rate limiting, or on the mail API.
// When too many jobs are in flight the request is dropped; the caller still
// answers 202.
func (s *MagicLinkService) Submit(req MagicLinkRequest) {
	select {
	case s.sem <- struct{}{}:
	default:
		log.Warn().Msg("magic link: too many requests in flight; dropped")
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.sem }()
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("magic link: request job panicked")
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), magicLinkJobTimeout)
		defer cancel()
		s.process(ctx, req)
	}()
}

// NormalizeEmail lowercases and trims; ok is false for anything that is not a
// plain single address.
func NormalizeEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" || len(e) > 254 {
		return e, false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" {
		return e, false
	}
	return e, true
}

func (s *MagicLinkService) limits() (emailLimit, ipLimit int, window time.Duration) {
	c := s.cfg.MagicLink
	window = c.LimitWindow
	if window <= 0 {
		window = 15 * time.Minute
	}
	return c.EmailLimit, c.IPLimit, window
}

func (s *MagicLinkService) ttl() time.Duration {
	if s.cfg.MagicLink.TTL > 0 {
		return s.cfg.MagicLink.TTL
	}
	return 15 * time.Minute
}

func (s *MagicLinkService) process(ctx context.Context, req MagicLinkRequest) {
	email, emailOK := NormalizeEmail(req.Email)
	emailLimit, ipLimit, window := s.limits()

	// Always evaluate both counters so one cannot mask the other.
	h := sha256.Sum256([]byte(email))
	ipAllowed := s.limiter.Allow(ctx, "magiclink:ip:"+req.IP, ipLimit, window)
	emailAllowed := s.limiter.Allow(ctx, "magiclink:email:"+hex.EncodeToString(h[:]), emailLimit, window)

	// Generate the token before any branch so the work is the same either way.
	token, tokenErr := security.GenerateOpaqueToken()

	if !emailOK || !ipAllowed || !emailAllowed || tokenErr != nil {
		return
	}
	org, err := s.tenants.ResolveTenant(ctx, req.Tenant)
	if err != nil {
		log.Error().Err(err).Msg("magic link: tenant lookup failed")
		return
	}
	if org == nil {
		return
	}
	redirect := ""
	if security.MagicLinkRedirectAllowed(s.cfg.MagicLink.RedirectAllowlist, req.RedirectTo) {
		redirect = req.RedirectTo
	}
	challenge := ""
	if s.cfg.MagicLink.CodeFlow {
		if !ValidCodeChallenge(req.CodeChallenge) {
			return // the handler already rejects this; never mint a code-flow link without one
		}
		challenge = req.CodeChallenge
	}
	now := time.Now()
	rec := &auth_repo.MagicLinkToken{
		ID:             uuid.New(),
		TokenHash:      security.HashToken(token),
		OrganizationID: org.ID,
		Email:          email,
		RedirectTo:     redirect,
		CodeChallenge:  challenge,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.ttl()),
	}
	if err := s.store.Create(ctx, rec); err != nil {
		log.Error().Err(err).Msg("magic link: store token failed")
		return
	}
	if err := s.mailer.SendMagicLink(ctx, email, s.BuildLink(token, org.Slug)); err != nil {
		log.Error().Err(err).Msg("magic link: send failed")
	}
}

// BuildLink returns the verify URL for a token.
func (s *MagicLinkService) BuildLink(token, tenantSlug string) string {
	base := strings.TrimSuffix(strings.TrimSpace(s.cfg.MagicLink.BaseURL), "/")
	path := strings.TrimSuffix(s.cfg.APIBasePath, "/")
	if path == "" {
		path = "/api/v1"
	}
	q := url.Values{}
	q.Set("token", token)
	q.Set("tenant", tenantSlug)
	return base + path + "/magic-link/verify?" + q.Encode()
}

// Verify redeems token exactly once. tenant, when non-empty, must resolve to
// the organization the token was issued for; a mismatch does not consume it.
func (s *MagicLinkService) Verify(ctx context.Context, token, tenant, ip, ua string) (*MagicLinkVerified, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > magicLinkTokenMaxLen {
		return nil, ErrMagicLinkInvalid
	}
	var orgFilter *uuid.UUID
	if strings.TrimSpace(tenant) != "" {
		org, err := s.tenants.ResolveTenant(ctx, tenant)
		if err != nil || org == nil {
			return nil, ErrMagicLinkInvalid
		}
		orgFilter = &org.ID
	}
	rec, err := s.store.Consume(ctx, security.HashToken(token), orgFilter)
	if err != nil {
		log.Error().Err(err).Msg("magic link: consume failed")
		return nil, ErrMagicLinkInvalid
	}
	if rec == nil {
		return nil, ErrMagicLinkInvalid
	}
	org, err := s.tenants.ResolveTenant(ctx, rec.OrganizationID.String())
	if err != nil || org == nil {
		return nil, ErrMagicLinkInvalid
	}

	if s.accounts == nil {
		return nil, ErrMagicLinkInvalid
	}
	user, created, err := s.accounts.FindOrCreate(ctx, rec.Email, ip, ua)
	if err != nil || user == nil {
		if err != nil {
			log.Error().Err(err).Msg("magic link: user provisioning failed")
		}
		return nil, ErrMagicLinkInvalid
	}
	if user.Status != "active" {
		return nil, ErrMagicLinkInvalid
	}
	if !created {
		if !s.accountMayUseMagicLink(ctx, user) {
			return nil, ErrMagicLinkInvalid
		}
		if !user.EmailVerified {
			// First proof of inbox ownership: nothing the account held before
			// (password, sessions, MFA) can be trusted.
			if err := s.accounts.TakeOver(ctx, user.ID); err != nil {
				log.Error().Err(err).Msg("magic link: account takeover hardening failed")
				return nil, ErrMagicLinkInvalid
			}
			user.EmailVerified = true
		}
	}

	redirect := ""
	if security.MagicLinkRedirectAllowed(s.cfg.MagicLink.RedirectAllowlist, rec.RedirectTo) {
		redirect = rec.RedirectTo
	}
	return &MagicLinkVerified{User: user, Organization: org, RedirectTo: redirect, CodeChallenge: rec.CodeChallenge, Created: created}, nil
}

// accountMayUseMagicLink refuses staff and admin accounts, and accounts with a
// password credential unless MagicLink.AllowPasswordAccounts is set. Every
// refusal, and every lookup error, is the same generic failure to the caller.
func (s *MagicLinkService) accountMayUseMagicLink(ctx context.Context, user *auth.UserAuth) bool {
	staff, err := s.accounts.IsStaff(ctx, user.ID)
	if err != nil {
		log.Error().Err(err).Msg("magic link: staff check failed")
		return false
	}
	if staff {
		log.Info().Str("user_id", user.ID.String()).Msg("magic link: refused for staff/admin account")
		return false
	}
	if s.cfg.MagicLink.AllowPasswordAccounts {
		return true
	}
	hasPassword, err := s.accounts.HasPassword(ctx, user.ID)
	if err != nil {
		log.Error().Err(err).Msg("magic link: credential check failed")
		return false
	}
	if hasPassword {
		log.Info().Str("user_id", user.ID.String()).Msg("magic link: refused for account with a password")
		return false
	}
	return true
}

// dbMagicLinkAccounts is the database-backed MagicLinkAccounts.
type dbMagicLinkAccounts struct {
	cfg     *apptypes.AppConfig
	users   *auth_repo.UserAuthRepo
	account *AccountService
	creds   *auth_repo.CredentialRepo
	factors *auth_repo.FactorRepo
	staff   StaffFunc
}

var errMagicLinkGuardsUnwired = errors.New("magic link account guards are not configured")

func (d *dbMagicLinkAccounts) FindOrCreate(ctx context.Context, email, ip, ua string) (*auth.UserAuth, bool, error) {
	u, err := d.users.GetByEmailFold(ctx, email)
	if err != nil {
		return nil, false, err
	}
	if u != nil {
		return u, false, nil
	}
	if d.cfg.DisablePublicSignup {
		return nil, false, nil
	}
	id, err := d.account.CreatePasswordlessAccount(ctx, email, ip, ua)
	if err != nil {
		// A concurrent verify for the same new address may have won the insert.
		if again, e := d.users.GetByEmailFold(ctx, email); e == nil && again != nil {
			return again, false, nil
		}
		return nil, false, err
	}
	u, err = d.users.GetByID(ctx, id)
	return u, true, err
}

func (d *dbMagicLinkAccounts) IsStaff(ctx context.Context, userID uuid.UUID) (bool, error) {
	if d.staff == nil {
		return false, errMagicLinkGuardsUnwired
	}
	return d.staff(ctx, userID)
}

func (d *dbMagicLinkAccounts) HasPassword(ctx context.Context, userID uuid.UUID) (bool, error) {
	if d.creds == nil {
		return false, errMagicLinkGuardsUnwired
	}
	c, err := d.creds.GetByUserID(ctx, userID)
	return c != nil, err
}

func (d *dbMagicLinkAccounts) TakeOver(ctx context.Context, userID uuid.UUID) error {
	if d.creds == nil || d.factors == nil {
		return errMagicLinkGuardsUnwired
	}
	authSvc := d.account.authSvc
	if _, err := authSvc.RevokeAllSessionsForUser(ctx, userID); err != nil {
		return err
	}
	if err := d.creds.DeleteByUserID(ctx, userID); err != nil {
		return err
	}
	factors, err := d.factors.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, f := range factors {
		if err := d.factors.Delete(ctx, f.ID, userID); err != nil {
			return err
		}
	}
	if err := d.factors.DeleteRecoveryCodes(ctx, userID); err != nil {
		return err
	}
	return authSvc.MarkEmailVerified(ctx, userID)
}

// expiredPurger is implemented by the repositories.
type expiredPurger interface {
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// PurgeExpired deletes expired tokens and codes.
func (s *MagicLinkService) PurgeExpired(ctx context.Context) {
	now := time.Now()
	for name, store := range map[string]any{"tokens": s.store, "codes": s.codes} {
		p, ok := store.(expiredPurger)
		if !ok {
			continue
		}
		n, err := p.DeleteExpired(ctx, now)
		if err != nil {
			log.Error().Err(err).Str("table", name).Msg("magic link: purge expired failed")
		} else if n > 0 {
			log.Debug().Int64("deleted", n).Str("table", name).Msg("magic link: purged expired rows")
		}
	}
}

// StartCleanup purges expired rows now and then every interval until ctx ends.
// The returned channel closes once the goroutine has exited.
func (s *MagicLinkService) StartCleanup(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("magic link: cleanup panicked")
			}
		}()
		s.PurgeExpired(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.PurgeExpired(ctx)
			}
		}
	}()
	return done
}
