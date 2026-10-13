package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Sydekse/authpad/internal/domain/auth"
	"github.com/Sydekse/authpad/internal/domain/idp"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ErrMagicCodeInvalid covers every exchange failure (unknown, expired, reused,
// wrong origin, dead session) so callers cannot tell them apart.
var ErrMagicCodeInvalid = errors.New("magic link code invalid or expired")

const (
	// MagicLinkCodeTTL is how long a one-time code can be exchanged.
	MagicLinkCodeTTL    = 60 * time.Second
	magicLinkCodeMaxLen = 128
)

// MagicLinkCodeStore persists code hashes.
type MagicLinkCodeStore interface {
	Create(ctx context.Context, c *auth_repo.MagicLinkCode) error
	Consume(ctx context.Context, codeHash string) (*auth_repo.MagicLinkCode, error)
}

// MagicLinkExchange is the result of a successful code exchange.
type MagicLinkExchange struct {
	SessionToken string
	ExpiresAt    time.Time
	User         *auth.UserAuth
	// OrgID is the tenant the link was issued for, set only when the user is an
	// active member of it. Signing in does not create membership.
	OrgID      *uuid.UUID
	IsMember   bool
	Role       string // the user's role in the tenant; empty for non-members
	MFAPending bool
}

// MembershipLookup reads organization membership.
type MembershipLookup interface {
	Membership(ctx context.Context, orgID, userID uuid.UUID) (*idp.OrganizationMembership, error)
}

// SetMembership wires the membership lookup used at exchange. Without it every
// exchange reports a non-member.
func (s *MagicLinkService) SetMembership(m MembershipLookup) { s.members = m }

// PKCEChallenge is the S256 code_challenge for verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validCodeVerifier checks RFC 7636 section 4.1: 43-128 unreserved characters.
func validCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

// EnableCodeFlow wires the one-time-code dependencies.
func (s *MagicLinkService) EnableCodeFlow(codes MagicLinkCodeStore, authSvc *AuthService) {
	s.codes = codes
	s.authSvc = authSvc
}

// CreateCode issues a one-time code bound to a session, tenant and the exact
// origin of redirectURL. Only the code's hash is stored.
func (s *MagicLinkService) CreateCode(ctx context.Context, sessionID, orgID uuid.UUID, redirectURL, codeChallenge string) (string, error) {
	if !ValidCodeChallenge(codeChallenge) {
		return "", ErrMagicCodeInvalid
	}
	origin, ok := security.OriginOfURL(redirectURL)
	if !ok {
		return "", ErrMagicCodeInvalid
	}
	code, err := security.GenerateOpaqueToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	err = s.codes.Create(ctx, &auth_repo.MagicLinkCode{
		ID:             uuid.New(),
		CodeHash:       security.HashToken(code),
		SessionID:      sessionID,
		OrganizationID: orgID,
		RedirectOrigin: origin,
		CodeChallenge:  codeChallenge,
		CreatedAt:      now,
		ExpiresAt:      now.Add(MagicLinkCodeTTL),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// Exchange consumes code exactly once. The code is burned even when the origin
// or the PKCE verifier does not match. The session's bearer token is replaced by a fresh one that
// is returned; the token produced at verify time is never stored.
func (s *MagicLinkService) Exchange(ctx context.Context, code, redirectOrigin, codeVerifier string) (*MagicLinkExchange, error) {
	if code == "" || len(code) > magicLinkCodeMaxLen || !validCodeVerifier(codeVerifier) {
		return nil, ErrMagicCodeInvalid
	}
	origin, originOK := security.NormalizeOrigin(redirectOrigin)
	rec, err := s.codes.Consume(ctx, security.HashToken(code))
	if err != nil {
		log.Error().Err(err).Msg("magic link: consume code failed")
		return nil, ErrMagicCodeInvalid
	}
	if rec == nil || !originOK || subtle.ConstantTimeCompare([]byte(origin), []byte(rec.RedirectOrigin)) != 1 {
		return nil, ErrMagicCodeInvalid
	}
	// An empty stored challenge (row from before PKCE) can never match.
	if !ValidCodeChallenge(rec.CodeChallenge) ||
		subtle.ConstantTimeCompare([]byte(PKCEChallenge(codeVerifier)), []byte(rec.CodeChallenge)) != 1 {
		return nil, ErrMagicCodeInvalid
	}
	token, userID, exp, pending, err := s.authSvc.IssueSessionToken(ctx, rec.SessionID)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			log.Error().Err(err).Msg("magic link: issue session token failed")
		}
		return nil, ErrMagicCodeInvalid
	}
	user, err := s.authSvc.GetUserByID(ctx, userID)
	if err != nil || user == nil || user.Status != "active" {
		_ = s.authSvc.RevokeSession(ctx, rec.SessionID)
		return nil, ErrMagicCodeInvalid
	}
	ex := &MagicLinkExchange{SessionToken: token, ExpiresAt: exp, User: user, MFAPending: pending}
	ex.OrgID, ex.IsMember, ex.Role = s.tenantMembership(ctx, rec.OrganizationID, userID)
	return ex, nil
}

// tenantMembership reports the tenant only for active members. Signing in by
// magic link creates no membership, so a stranger gets no org_id. Any lookup
// failure counts as a non-member.
func (s *MagicLinkService) tenantMembership(ctx context.Context, orgID, userID uuid.UUID) (*uuid.UUID, bool, string) {
	if s.members == nil {
		return nil, false, ""
	}
	m, err := s.members.Membership(ctx, orgID, userID)
	if err != nil {
		log.Error().Err(err).Msg("magic link: membership lookup failed")
		return nil, false, ""
	}
	if m == nil || m.Status != "active" {
		return nil, false, ""
	}
	return &orgID, true, m.Role
}

// AllowExchange applies the per-IP exchange limit.
func (s *MagicLinkService) AllowExchange(ctx context.Context, ip string) bool {
	limit := s.cfg.MagicLink.ExchangeLimit
	if limit <= 0 {
		return true
	}
	return s.limiter.Allow(ctx, "magiclink:exchange:"+ip, limit, time.Minute)
}

// CodeFlowActive reports whether the code flow is configured and wired.
func (s *MagicLinkService) CodeFlowActive() bool {
	return s.cfg.MagicLink.CodeFlow && s.CodeFlowReady()
}

// CodeFlowReady reports whether EnableCodeFlow has been called.
func (s *MagicLinkService) CodeFlowReady() bool { return s.codes != nil && s.authSvc != nil }
