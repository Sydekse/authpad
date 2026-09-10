package auth

import (
	"errors"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
)

type (
	Config           = apptypes.AppConfig
	SessionConfig    = apptypes.SessionConfig
	SecurityConfig   = apptypes.SecurityConfig
	PagesConfig      = apptypes.PagesConfig
	OAuthConfig      = apptypes.OAuthConfig
	EmailConfig      = apptypes.EmailConfig
	RoleDefinition   = apptypes.RoleDefinition
	Hooks            = apptypes.Hooks
	FieldType        = apptypes.FieldType
	ProfileField     = apptypes.ProfileField
	ProfileSchema    = apptypes.ProfileSchema
	ProfileInput     = apptypes.ProfileInput
	InvitationConfig = apptypes.InvitationConfig
	TenancyConfig    = apptypes.TenancyConfig
	Mailer           = apptypes.Mailer
)

const (
	FieldTypeString = apptypes.FieldTypeString
	FieldTypeEmail  = apptypes.FieldTypeEmail
	FieldTypeURL    = apptypes.FieldTypeURL
	FieldTypeInt    = apptypes.FieldTypeInt
	FieldTypeBool   = apptypes.FieldTypeBool
	FieldTypeJSON   = apptypes.FieldTypeJSON
)

func DefaultConfig() Config {
	return Config{
		Env: "development",
		Session: SessionConfig{
			TTL:           7 * 24 * time.Hour,
			IdleTimeout:   24 * time.Hour,
			MaxLifetime:   30 * 24 * time.Hour,
			RememberMeTTL: 30 * 24 * time.Hour,
			CookieName:    "session",
		},
		Security: SecurityConfig{
			AdminRoleName:  "admin",
			RateLimitRPM:   15,
			RateLimitBurst: 5,
			CSRFEnabled:    true,
			PasswordPolicy: apptypes.PasswordPolicy{MinLength: 8},
		},
		AllowedOrigins: []string{"http://localhost:3000"},
		Port:           "8080",
	}
}

func ValidateConfig(c *Config) error {
	if c == nil {
		return errors.New("config is nil")
	}
	return (*apptypes.AppConfig)(c).Validate()
}

func IdPEnabled(c Config) bool {
	return c.IdPDatabaseURL != ""
}

func ValidateProfile(schema ProfileSchema, raw map[string]any) (ProfileInput, error) {
	return apptypes.ProfileSchema(schema).ValidateProfile(raw)
}
