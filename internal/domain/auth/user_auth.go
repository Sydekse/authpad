package auth

import (
	"time"

	"github.com/google/uuid"
)

// UserAuth is the auth-side user record (Auth DB).
type UserAuth struct {
	ID            uuid.UUID  `json:"id"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Status        string     `json:"status"` // active, suspended, pending_deletion
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

// Credential is a password or other credential (Auth DB).
type Credential struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	CredentialType string    `json:"credential_type"` // password, etc.
	PasswordHash   string    `json:"-"`
	HashVersion    int       `json:"hash_version"` // 1=bcrypt(legacy), 2=argon2id
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Session is an opaque session (Auth DB).
type Session struct {
	ID           uuid.UUID  `json:"id"`
	UserID       uuid.UUID  `json:"user_id"`
	TokenHash    string     `json:"-"`
	IPAddress    string     `json:"ip_address,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastActiveAt time.Time  `json:"last_active_at"`
	Revoked      bool       `json:"revoked"`
}

// OAuthAccount is a linked OAuth provider account (Auth DB).
type OAuthAccount struct {
	ID                uuid.UUID  `json:"id"`
	UserID            uuid.UUID  `json:"user_id"`
	Provider          string     `json:"provider"` // github, google
	ProviderAccountID string     `json:"provider_account_id"`
	AccessTokenEnc    string     `json:"-"`
	RefreshTokenEnc   string     `json:"-"`
	TokenExpiresAt    *time.Time `json:"token_expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// Factor is an MFA factor (Auth DB).
type Factor struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	FactorType   string    `json:"factor_type"` // totp, webauthn
	SecretEnc    string    `json:"-"`
	Label        string    `json:"label,omitempty"`
	CredentialID string    `json:"-"`
	PublicKey    string    `json:"-"`
	SignCount    int64     `json:"-"`
	Verified     bool      `json:"verified"`
	CreatedAt    time.Time `json:"created_at"`
}

// PasswordResetToken is a one-time token for password reset (Auth DB).
type PasswordResetToken struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
