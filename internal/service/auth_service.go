package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/auth-project/goauth/internal/domain/auth"
	auth_repo "github.com/auth-project/goauth/internal/repository/auth"
	"github.com/auth-project/goauth/internal/security"
	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserNotFound           = errors.New("user not found")
	ErrSessionNotFound        = errors.New("session not found")
	ErrResetTokenInvalid      = errors.New("reset token invalid or expired")
	ErrNoPasswordCredential   = errors.New("user has no password credential")
	ErrEmailNotVerified       = errors.New("email not verified")
	ErrVerifyTokenInvalid     = errors.New("verification token invalid or expired")
	ErrWeakPassword           = errors.New("password does not meet policy")
)

// AuthService handles authentication (Auth DB only).
type AuthService struct {
	userRepo             *auth_repo.UserAuthRepo
	credRepo             *auth_repo.CredentialRepo
	sessionRepo          *auth_repo.SessionRepo
	resetTokenRepo       *auth_repo.PasswordResetTokenRepo
	verifyRepo           *auth_repo.EmailVerificationRepo
	factorRepo           *auth_repo.FactorRepo
	password             *security.PasswordService
	sessionCfg           apptypes.SessionConfig
	passwordPolicy       apptypes.PasswordPolicy
	requireVerification  bool
	resetTokenTTL        time.Duration
}

func NewAuthService(
	userRepo *auth_repo.UserAuthRepo,
	credRepo *auth_repo.CredentialRepo,
	sessionRepo *auth_repo.SessionRepo,
	resetTokenRepo *auth_repo.PasswordResetTokenRepo,
	verifyRepo *auth_repo.EmailVerificationRepo,
	factorRepo *auth_repo.FactorRepo,
	password *security.PasswordService,
	sessionCfg apptypes.SessionConfig,
	passwordPolicy apptypes.PasswordPolicy,
	requireVerification bool,
) *AuthService {
	if sessionCfg.TTL == 0 {
		sessionCfg.TTL = 7 * 24 * time.Hour
	}
	return &AuthService{
		userRepo:            userRepo,
		credRepo:            credRepo,
		sessionRepo:         sessionRepo,
		resetTokenRepo:      resetTokenRepo,
		verifyRepo:          verifyRepo,
		factorRepo:          factorRepo,
		password:            password,
		sessionCfg:          sessionCfg,
		passwordPolicy:      passwordPolicy,
		requireVerification: requireVerification,
		resetTokenTTL:       5 * time.Minute,
	}
}

func (s *AuthService) ValidatePasswordPolicy(password string) error {
	if len(password) < s.passwordPolicy.MinLength {
		return fmt.Errorf("%w: minimum length is %d", ErrWeakPassword, s.passwordPolicy.MinLength)
	}
	var upper, lower, number, special bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsNumber(r):
			number = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			special = true
		}
	}
	if s.passwordPolicy.RequireUppercase && !upper {
		return fmt.Errorf("%w: requires uppercase letter", ErrWeakPassword)
	}
	if s.passwordPolicy.RequireLowercase && !lower {
		return fmt.Errorf("%w: requires lowercase letter", ErrWeakPassword)
	}
	if s.passwordPolicy.RequireNumber && !number {
		return fmt.Errorf("%w: requires number", ErrWeakPassword)
	}
	if s.passwordPolicy.RequireSpecial && !special {
		return fmt.Errorf("%w: requires special character", ErrWeakPassword)
	}
	return nil
}

func (s *AuthService) CreateUserAuth(ctx context.Context, userID uuid.UUID, email string) error {
	now := time.Now()
	u := &auth.UserAuth{
		ID:            userID,
		Email:         email,
		EmailVerified: false,
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	return s.userRepo.Create(ctx, u)
}

func (s *AuthService) CreateCredential(ctx context.Context, userID uuid.UUID, plainPassword string) error {
	if err := s.ValidatePasswordPolicy(plainPassword); err != nil {
		return err
	}
	hash, err := s.password.Hash(plainPassword)
	if err != nil {
		return err
	}
	now := time.Now()
	c := &auth.Credential{
		ID:             uuid.New(),
		UserID:         userID,
		CredentialType: "password",
		PasswordHash:   hash,
		HashVersion:    2,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return s.credRepo.Create(ctx, c)
}

func (s *AuthService) ValidatePassword(ctx context.Context, email, password string) (*auth.UserAuth, error) {
	u, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || u == nil {
		return nil, ErrInvalidCredentials
	}
	if u.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	if s.requireVerification && !u.EmailVerified {
		return nil, ErrEmailNotVerified
	}
	cred, err := s.credRepo.GetByUserID(ctx, u.ID)
	if err != nil || cred == nil {
		return nil, ErrInvalidCredentials
	}
	ok, err := s.password.Verify(password, cred.PasswordHash)
	if err != nil || !ok {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func (s *AuthService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (token string, sess *auth.Session, err error) {
	token, err = security.GenerateOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	tokenHash := security.HashToken(token)
	now := time.Now()
	expiresAt := now.Add(s.sessionCfg.TTL)
	if s.sessionCfg.MaxLifetime > 0 && expiresAt.After(now.Add(s.sessionCfg.MaxLifetime)) {
		expiresAt = now.Add(s.sessionCfg.MaxLifetime)
	}
	sess = &auth.Session{
		ID:           uuid.New(),
		UserID:       userID,
		TokenHash:    tokenHash,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		LastActiveAt: now,
		Revoked:      false,
	}
	if err := s.sessionRepo.Create(ctx, sess); err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*auth.UserAuth, error) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *AuthService) GetSessionByToken(ctx context.Context, token string) (*auth.Session, error) {
	tokenHash := security.HashToken(token)
	sess, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil || sess == nil {
		return nil, ErrSessionNotFound
	}
	if s.sessionCfg.IdleTimeout > 0 && time.Since(sess.LastActiveAt) > s.sessionCfg.IdleTimeout {
		_ = s.sessionRepo.RevokeByID(ctx, sess.ID)
		return nil, ErrSessionNotFound
	}
	if s.sessionCfg.MaxLifetime > 0 && time.Since(sess.CreatedAt) > s.sessionCfg.MaxLifetime {
		_ = s.sessionRepo.RevokeByID(ctx, sess.ID)
		return nil, ErrSessionNotFound
	}
	_ = s.sessionRepo.UpdateLastActive(ctx, sess.ID)
	return sess, nil
}

func (s *AuthService) RotateSession(ctx context.Context, sess *auth.Session) (string, *auth.Session, error) {
	if s.sessionCfg.RotateInterval <= 0 {
		return "", sess, nil
	}
	if time.Since(sess.CreatedAt) < s.sessionCfg.RotateInterval {
		return "", sess, nil
	}
	token, err := security.GenerateOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	expiresAt := time.Now().Add(s.sessionCfg.TTL)
	if err := s.sessionRepo.RotateToken(ctx, sess.ID, security.HashToken(token), expiresAt); err != nil {
		return "", nil, err
	}
	sess.ExpiresAt = expiresAt
	return token, sess, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	return s.sessionRepo.RevokeByID(ctx, sessionID)
}

func (s *AuthService) RevokeAllSessionsForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	return s.sessionRepo.RevokeAllForUser(ctx, userID)
}

func (s *AuthService) ListSessions(ctx context.Context, userID uuid.UUID) ([]auth.Session, error) {
	return s.sessionRepo.ListByUserID(ctx, userID)
}

func (s *AuthService) CreatePasswordResetToken(ctx context.Context, email string) (token string, err error) {
	u, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || u == nil {
		return "", nil
	}
	if u.Status != "active" {
		return "", nil
	}
	cred, err := s.credRepo.GetByUserID(ctx, u.ID)
	if err != nil || cred == nil {
		return "", nil
	}
	rawToken, err := security.GenerateOpaqueToken()
	if err != nil {
		return "", err
	}
	tokenHash := security.HashToken(rawToken)
	now := time.Now()
	t := &auth.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(s.resetTokenTTL),
		CreatedAt: now,
	}
	if err := s.resetTokenRepo.Create(ctx, t); err != nil {
		return "", err
	}
	return rawToken, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if err := s.ValidatePasswordPolicy(newPassword); err != nil {
		return err
	}
	tokenHash := security.HashToken(rawToken)
	t, err := s.resetTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil || t == nil {
		return ErrResetTokenInvalid
	}
	cred, err := s.credRepo.GetByUserID(ctx, t.UserID)
	if err != nil || cred == nil {
		return ErrNoPasswordCredential
	}
	hash, err := s.password.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := s.credRepo.UpdateHash(ctx, cred.ID, hash, 2); err != nil {
		return err
	}
	return s.resetTokenRepo.DeleteByID(ctx, t.ID)
}

func (s *AuthService) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID) (string, error) {
	rawToken, err := security.GenerateOpaqueToken()
	if err != nil {
		return "", err
	}
	if err := s.verifyRepo.Create(ctx, userID, security.HashToken(rawToken), time.Now().Add(24*time.Hour)); err != nil {
		return "", err
	}
	return rawToken, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, rawToken string) error {
	userID, err := s.verifyRepo.GetByTokenHash(ctx, security.HashToken(strings.TrimSpace(rawToken)))
	if err != nil || userID == uuid.Nil {
		return ErrVerifyTokenInvalid
	}
	if err := s.userRepo.SetEmailVerified(ctx, userID); err != nil {
		return err
	}
	return s.verifyRepo.DeleteByUserID(ctx, userID)
}

func (s *AuthService) DeleteUserAuth(ctx context.Context, userID uuid.UUID) error {
	_, _ = s.sessionRepo.RevokeAllForUser(ctx, userID)
	_ = s.credRepo.DeleteByUserID(ctx, userID)
	return s.userRepo.Anonymize(ctx, userID)
}

func (s *AuthService) RollbackUser(ctx context.Context, userID uuid.UUID) {
	_ = s.credRepo.DeleteByUserID(ctx, userID)
	_ = s.userRepo.Delete(ctx, userID)
}

func (s *AuthService) FactorRepo() *auth_repo.FactorRepo {
	return s.factorRepo
}
