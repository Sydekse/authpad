package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/auth-project/authpad/internal/domain/auth"
	auth_repo "github.com/auth-project/authpad/internal/repository/auth"
	"github.com/auth-project/authpad/internal/security"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

var ErrMFARequired = errors.New("mfa verification required")
var ErrMFAInvalid = errors.New("invalid mfa code")

type MFAService struct {
	factorRepo *auth_repo.FactorRepo
	authSvc    *AuthService
	auditSvc   *AuditService
	secret     string
	issuer     string
}

func NewMFAService(factorRepo *auth_repo.FactorRepo, authSvc *AuthService, auditSvc *AuditService, sessionSecret, issuer string) *MFAService {
	if strings.TrimSpace(issuer) == "" {
		issuer = "Sydek Auth"
	}
	return &MFAService{factorRepo: factorRepo, authSvc: authSvc, auditSvc: auditSvc, secret: sessionSecret, issuer: issuer}
}

type TOTPEnrollResult struct {
	FactorID string `json:"factor_id"`
	Secret   string `json:"secret"`
	URI      string `json:"uri"`
}

func (s *MFAService) EnrollTOTP(ctx context.Context, userID uuid.UUID, label string) (*TOTPEnrollResult, error) {
	accountName := strings.TrimSpace(label)
	if accountName == "" {
		accountName = "account"
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: accountName,
	})
	if err != nil {
		return nil, err
	}
	factorID := uuid.New()
	f := &auth.Factor{
		ID:         factorID,
		UserID:     userID,
		FactorType: "totp",
		SecretEnc:  key.Secret(),
		Label:      label,
		Verified:   false,
		CreatedAt:  time.Now(),
	}
	if err := s.factorRepo.Create(ctx, f); err != nil {
		return nil, err
	}
	return &TOTPEnrollResult{
		FactorID: factorID.String(),
		Secret:   key.Secret(),
		URI:      key.URL(),
	}, nil
}

func (s *MFAService) VerifyTOTP(ctx context.Context, userID uuid.UUID, factorID uuid.UUID, code string) error {
	f, err := s.factorRepo.GetByID(ctx, factorID)
	if err != nil || f == nil || f.UserID != userID || f.FactorType != "totp" {
		return ErrMFAInvalid
	}
	if !totp.Validate(code, f.SecretEnc) {
		return ErrMFAInvalid
	}
	if !f.Verified {
		if err := s.factorRepo.MarkVerified(ctx, factorID); err != nil {
			return err
		}
		if s.auditSvc != nil {
			s.auditSvc.LogAuth(ctx, &userID, "mfa.enrolled", "", "", map[string]any{"type": "totp"})
		}
	}
	return nil
}

func (s *MFAService) DeleteFactor(ctx context.Context, userID, factorID uuid.UUID) error {
	if err := s.factorRepo.Delete(ctx, factorID, userID); err != nil {
		return err
	}
	if s.auditSvc != nil {
		s.auditSvc.LogAuth(ctx, &userID, "mfa.removed", "", "", map[string]any{"factor_id": factorID.String()})
	}
	return nil
}

func (s *MFAService) GenerateRecoveryCodes(ctx context.Context, userID uuid.UUID, count int) ([]string, error) {
	if count <= 0 {
		count = 8
	}
	_ = s.factorRepo.DeleteRecoveryCodes(ctx, userID)
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		buf := make([]byte, 5)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		codes = append(codes, code)
		if err := s.factorRepo.CreateRecoveryCode(ctx, userID, security.HashToken(code)); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func (s *MFAService) UseRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	return s.factorRepo.UseRecoveryCode(ctx, userID, security.HashToken(code))
}

func (s *MFAService) ListFactors(ctx context.Context, userID uuid.UUID) ([]auth.Factor, error) {
	return s.factorRepo.ListByUserID(ctx, userID)
}

func (s *MFAService) StoreWebAuthnFactor(ctx context.Context, userID uuid.UUID, label, credentialID, publicKey string) (*auth.Factor, error) {
	f := &auth.Factor{
		ID:           uuid.New(),
		UserID:       userID,
		FactorType:   "webauthn",
		Label:        label,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		Verified:     true,
		CreatedAt:    time.Now(),
	}
	if err := s.factorRepo.Create(ctx, f); err != nil {
		return nil, err
	}
	if s.auditSvc != nil {
		s.auditSvc.LogAuth(ctx, &userID, "mfa.enrolled", "", "", map[string]any{"type": "webauthn"})
	}
	return f, nil
}

func RandomChallenge() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *MFAService) UserHasMFA(ctx context.Context, userID uuid.UUID) (bool, error) {
	factors, err := s.factorRepo.ListByUserID(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, f := range factors {
		if f.Verified {
			return true, nil
		}
	}
	return false, nil
}

func (s *MFAService) FormatError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w", err)
}
