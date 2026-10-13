package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/Sydekse/authpad/internal/domain/auth"
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
	OrgID        uuid.UUID
	MFAPending   bool
}

// EnableCodeFlow wires the one-time-code dependencies.
func (s *MagicLinkService) EnableCodeFlow(codes MagicLinkCodeStore, authSvc *AuthService) {
	s.codes = codes
	s.authSvc = authSvc
}

// CreateCode issues a one-time code bound to a session, tenant and the exact
// origin of redirectURL. Only the code's hash is stored.
func (s *MagicLinkService) CreateCode(ctx context.Context, sessionID, orgID uuid.UUID, redirectURL string) (string, error) {
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
		CreatedAt:      now,
		ExpiresAt:      now.Add(MagicLinkCodeTTL),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// Exchange consumes code exactly once. The code is burned even when the origin
// does not match. The session's bearer token is replaced by a fresh one that
// is returned; the token produced at verify time is never stored.
func (s *MagicLinkService) Exchange(ctx context.Context, code, redirectOrigin string) (*MagicLinkExchange, error) {
	if code == "" || len(code) > magicLinkCodeMaxLen {
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
	return &MagicLinkExchange{SessionToken: token, ExpiresAt: exp, User: user, OrgID: rec.OrganizationID, MFAPending: pending}, nil
}

// AllowExchange applies the per-IP exchange limit.
func (s *MagicLinkService) AllowExchange(ctx context.Context, ip string) bool {
	limit := s.cfg.MagicLink.ExchangeLimit
	if limit <= 0 {
		return true
	}
	return s.limiter.Allow(ctx, "magiclink:exchange:"+ip, limit, time.Minute)
}

// CodeFlowReady reports whether EnableCodeFlow has been called.
func (s *MagicLinkService) CodeFlowReady() bool { return s.codes != nil && s.authSvc != nil }
