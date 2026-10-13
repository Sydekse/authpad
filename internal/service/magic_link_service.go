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
}

type MagicLinkVerified struct {
	User         *auth.UserAuth
	Organization *idp.Organization
	RedirectTo   string // validated against the allowlist; empty means use the default
	Created      bool
}

// MagicLinkService issues and redeems passwordless sign-in links.
type MagicLinkService struct {
	cfg     *apptypes.AppConfig
	store   MagicLinkStore
	tenants TenantResolver
	mailer  apptypes.MagicLinkMailer
	limiter security.WindowLimiter

	// Verify-side dependencies. Nil in request-only unit tests.
	users   *auth_repo.UserAuthRepo
	account *AccountService

	// Code-flow dependencies; set by EnableCodeFlow.
	codes   MagicLinkCodeStore
	authSvc *AuthService

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
	return &MagicLinkService{
		cfg: cfg, store: store, tenants: tenants, mailer: mailer, limiter: limiter,
		users: users, account: account,
		sem: make(chan struct{}, magicLinkMaxInFlight),
	}
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
	now := time.Now()
	rec := &auth_repo.MagicLinkToken{
		ID:             uuid.New(),
		TokenHash:      security.HashToken(token),
		OrganizationID: org.ID,
		Email:          email,
		RedirectTo:     redirect,
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

	user, created, err := s.findOrCreateUser(ctx, rec.Email, ip, ua)
	if err != nil || user == nil {
		if err != nil {
			log.Error().Err(err).Msg("magic link: user provisioning failed")
		}
		return nil, ErrMagicLinkInvalid
	}
	if user.Status != "active" {
		return nil, ErrMagicLinkInvalid
	}
	if !user.EmailVerified {
		// The link was delivered to this inbox, which proves ownership.
		if err := s.account.authSvc.MarkEmailVerified(ctx, user.ID); err != nil {
			return nil, ErrMagicLinkInvalid
		}
		user.EmailVerified = true
	}

	redirect := ""
	if security.MagicLinkRedirectAllowed(s.cfg.MagicLink.RedirectAllowlist, rec.RedirectTo) {
		redirect = rec.RedirectTo
	}
	return &MagicLinkVerified{User: user, Organization: org, RedirectTo: redirect, Created: created}, nil
}

func (s *MagicLinkService) findOrCreateUser(ctx context.Context, email, ip, ua string) (*auth.UserAuth, bool, error) {
	u, err := s.users.GetByEmailFold(ctx, email)
	if err != nil {
		return nil, false, err
	}
	if u != nil {
		return u, false, nil
	}
	if s.cfg.DisablePublicSignup {
		return nil, false, nil
	}
	id, err := s.account.CreatePasswordlessAccount(ctx, email, ip, ua)
	if err != nil {
		// A concurrent verify for the same new address may have won the insert.
		if again, e := s.users.GetByEmailFold(ctx, email); e == nil && again != nil {
			return again, false, nil
		}
		return nil, false, err
	}
	u, err = s.users.GetByID(ctx, id)
	return u, true, err
}
