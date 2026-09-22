package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/domain/auth"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/google/uuid"
)

var ErrSuspended = errors.New("account suspended")

// Account is a credential-store user, without a session.
type Account struct {
	ID            uuid.UUID
	Email         string
	Status        string
	EmailVerified bool
	CreatedAt     time.Time
}

// LoginResult is a new session. MFARequired means the session cookie is issued
// but product calls must wait for CompleteMFA.
type LoginResult struct {
	UserID      uuid.UUID
	Email       string
	Token       string
	SessionID   uuid.UUID
	MFARequired bool
	ExpiresAt   time.Time
}

// TOTPEnrollment is the authenticator secret shown once at enroll time.
type TOTPEnrollment struct {
	FactorID      uuid.UUID
	Secret        string
	URI           string
	RecoveryCodes []string
}

// ImportAccountRequest creates a user from an existing password hash.
// ID may be uuid.Nil. An existing email returns that account and does not reset the password.
type ImportAccountRequest struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	EmailVerified bool
}

func (a *Auth) AccountByEmail(ctx context.Context, email string) (*Account, error) {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return nil, errors.New("auth is not initialized")
	}
	u, err := a.srv.AuthSvc.GetUserByEmail(ctx, strings.TrimSpace(email))
	if err != nil || u == nil {
		return nil, err
	}
	return accountFrom(u), nil
}

func (a *Auth) AccountByID(ctx context.Context, id uuid.UUID) (*Account, error) {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return nil, errors.New("auth is not initialized")
	}
	u, err := a.srv.AuthSvc.GetUserByID(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	return accountFrom(u), nil
}

func accountFrom(u *auth.UserAuth) *Account {
	return &Account{ID: u.ID, Email: u.Email, Status: u.Status, EmailVerified: u.EmailVerified, CreatedAt: u.CreatedAt}
}

func (a *Auth) GlobalRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if a == nil || a.srv == nil || a.srv.IdPSvc == nil {
		return nil, errors.New("idp is not enabled")
	}
	return a.srv.IdPSvc.GetRoleNames(ctx, userID)
}

func (a *Auth) UserHasMFA(ctx context.Context, userID uuid.UUID) (bool, error) {
	if a == nil || a.srv == nil || a.srv.MFASvc == nil {
		return false, errors.New("mfa is not initialized")
	}
	return a.srv.MFASvc.UserHasMFA(ctx, userID)
}

func (a *Auth) LockAccount(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return errors.New("auth is not initialized")
	}
	return a.srv.AuthSvc.LockUser(ctx, userID)
}

func (a *Auth) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return errors.New("auth is not initialized")
	}
	return a.srv.AuthSvc.UnlockUser(ctx, userID)
}

func (a *Auth) SetUserStatus(ctx context.Context, userID uuid.UUID, status string) error {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return errors.New("auth is not initialized")
	}
	return a.srv.AuthSvc.SetStatus(ctx, userID, status)
}

func (a *Auth) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return errors.New("auth is not initialized")
	}
	_, err := a.srv.AuthSvc.RevokeAllSessionsForUser(ctx, userID)
	return err
}

func (a *Auth) LogoutSession(ctx context.Context, sessionID uuid.UUID) error {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return errors.New("auth is not initialized")
	}
	return a.srv.AuthSvc.RevokeSession(ctx, sessionID)
}

// Login checks the password and issues a session. A verified TOTP factor leaves the session MFA-pending.
func (a *Auth) Login(ctx context.Context, email, password, ip, ua string) (*LoginResult, error) {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return nil, errors.New("auth is not initialized")
	}
	email = strings.TrimSpace(email)
	existing, err := a.srv.AuthSvc.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status != "active" && existing.Status != "locked" {
		return nil, ErrSuspended
	}
	user, err := a.srv.AuthSvc.ValidatePassword(ctx, email, password)
	if err != nil {
		if errors.Is(err, service.ErrAccountLocked) {
			return nil, ErrAccountLocked
		}
		return nil, err
	}
	ttl := a.config().Session.TTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	token, sess, err := a.srv.AuthSvc.CreateSessionWithTTL(ctx, user.ID, ip, ua, ttl)
	if err != nil {
		return nil, err
	}
	out := &LoginResult{
		UserID:    user.ID,
		Email:     user.Email,
		Token:     token,
		SessionID: sess.ID,
		ExpiresAt: sess.ExpiresAt,
	}
	if a.srv.OrgSvc != nil {
		if orgs, err := a.srv.OrgSvc.ListForUser(ctx, user.ID); err == nil && len(orgs) == 1 {
			_ = a.srv.OrgSvc.SwitchActive(ctx, sess.ID, user.ID, orgs[0].ID)
		}
	}
	if a.srv.MFASvc != nil {
		if has, err := a.srv.MFASvc.UserHasMFA(ctx, user.ID); err == nil && has {
			if err := a.srv.AuthSvc.SetSessionMFAPending(ctx, sess.ID, true); err != nil {
				return nil, err
			}
			out.MFARequired = true
		}
	}
	return out, nil
}

// ConfirmTOTP checks an authenticator code and marks that factor verified.
func (a *Auth) ConfirmTOTP(ctx context.Context, userID, factorID uuid.UUID, code string) error {
	if a == nil || a.srv == nil || a.srv.MFASvc == nil {
		return errors.New("mfa is not initialized")
	}
	return a.srv.MFASvc.VerifyTOTP(ctx, userID, factorID, code)
}

// CompleteMFA verifies a TOTP or recovery code and clears the pending flag.
func (a *Auth) CompleteMFA(ctx context.Context, sessionID, userID uuid.UUID, code string) error {
	if a == nil || a.srv == nil || a.srv.MFASvc == nil || a.srv.AuthSvc == nil {
		return errors.New("mfa is not initialized")
	}
	if err := a.srv.MFASvc.VerifyLoginCode(ctx, userID, nil, code); err != nil {
		return err
	}
	return a.srv.AuthSvc.SetSessionMFAPending(ctx, sessionID, false)
}

// EnrollTOTP starts authenticator enrollment and returns recovery codes.
func (a *Auth) EnrollTOTP(ctx context.Context, userID uuid.UUID, label string) (*TOTPEnrollment, error) {
	if a == nil || a.srv == nil || a.srv.MFASvc == nil {
		return nil, errors.New("mfa is not initialized")
	}
	if strings.TrimSpace(label) == "" {
		label = "Authenticator"
	}
	result, err := a.srv.MFASvc.EnrollTOTP(ctx, userID, label)
	if err != nil {
		return nil, err
	}
	factorID, err := uuid.Parse(result.FactorID)
	if err != nil {
		return nil, err
	}
	codes, err := a.srv.MFASvc.GenerateRecoveryCodes(ctx, userID, 8)
	if err != nil {
		return nil, err
	}
	return &TOTPEnrollment{
		FactorID:      factorID,
		Secret:        result.Secret,
		URI:           result.URI,
		RecoveryCodes: codes,
	}, nil
}

// ImportAccount inserts a user with a precomputed password hash. An existing email is returned as-is.
func (a *Auth) ImportAccount(ctx context.Context, req ImportAccountRequest) (uuid.UUID, error) {
	if a == nil || a.srv == nil || a.srv.AuthSvc == nil {
		return uuid.Nil, errors.New("auth is not initialized")
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	existing, err := a.srv.AuthSvc.GetUserByEmail(ctx, email)
	if err != nil {
		return uuid.Nil, err
	}
	if existing != nil {
		return existing.ID, nil
	}
	id := req.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	if err := a.srv.AuthSvc.CreateUserAuth(ctx, id, email); err != nil {
		return uuid.Nil, err
	}
	if err := a.srv.AuthSvc.ImportCredential(ctx, id, req.PasswordHash); err != nil {
		a.srv.AuthSvc.RollbackUser(ctx, id)
		return uuid.Nil, err
	}
	if req.EmailVerified {
		_ = a.srv.AuthSvc.MarkEmailVerified(ctx, id)
	}
	return id, nil
}

// Membership returns the caller's membership in an organization, if any.
func (a *Auth) Membership(ctx context.Context, orgID, userID uuid.UUID) (*OrganizationMembership, error) {
	s, err := a.orgSvc()
	if err != nil {
		return nil, err
	}
	return s.Membership(ctx, orgID, userID)
}

// ErrInvalidCredentials is the password failure from the auth service.
var ErrInvalidCredentials = service.ErrInvalidCredentials
