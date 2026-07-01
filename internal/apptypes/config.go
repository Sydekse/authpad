package apptypes

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type SessionConfig struct {
	TTL            time.Duration
	IdleTimeout    time.Duration
	MaxLifetime    time.Duration
	RotateInterval time.Duration
	CookieDomain   string
	CookieSecure   bool
	CookieName     string
}

type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

type SecurityConfig struct {
	PepperKey      string
	SessionSecret  string
	ServiceKeys    map[string]string
	AdminRoleName  string
	RateLimitRPM   int
	RateLimitBurst int
	RedisURL       string
	CSRFEnabled    bool
	PasswordPolicy PasswordPolicy
}

type PagesConfig struct {
	SignInURL        string
	SignUpURL        string
	VerifyEmailURL   string
	ResetPasswordURL string
	CallbackURL      string
	ErrorURL         string
	AppName          string
}

type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	AllowedRedirects   []string
}

type EmailConfig struct {
	ResendAPIKey        string
	ResendFrom          string
	RequireVerification bool
	AppName             string
}

type RoleDefinition struct {
	Name        string
	Description string
}

type Hooks struct {
	OnRoleAssigned func(ctx context.Context, userID uuid.UUID, role string) error
	OnSignup       func(ctx context.Context, userID uuid.UUID, email string) error
	OnLogin        func(ctx context.Context, userID uuid.UUID) error
	OnDelete       func(ctx context.Context, userID uuid.UUID) error
}

type FieldType string

const (
	FieldTypeString FieldType = "string"
	FieldTypeEmail  FieldType = "email"
	FieldTypeURL    FieldType = "url"
	FieldTypeInt    FieldType = "int"
	FieldTypeBool   FieldType = "bool"
	FieldTypeJSON   FieldType = "json"
)

type ProfileField struct {
	Name     string
	Type     FieldType
	Required bool
	Unique   bool
	Validate func(any) error
}

type ProfileSchema struct {
	Fields []ProfileField
}

type ProfileInput struct {
	Name     string
	ImageURL string
	Bio      string
	Metadata map[string]any
}

type AppConfig struct {
	AuthDatabaseURL string
	IdPDatabaseURL  string
	Env             string
	Session         SessionConfig
	Security        SecurityConfig
	Pages           PagesConfig
	OAuth           OAuthConfig
	Email           EmailConfig
	Hooks           Hooks
	ProfileSchema   ProfileSchema
	Roles           []RoleDefinition
	AllowedOrigins  []string
	Port            string
}

func (c AppConfig) IdPEnabled() bool {
	return c.IdPDatabaseURL != ""
}
