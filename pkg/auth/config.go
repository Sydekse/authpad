package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/auth-project/goauth/internal/apptypes"
)

type (
	Config         = apptypes.AppConfig
	SessionConfig  = apptypes.SessionConfig
	SecurityConfig = apptypes.SecurityConfig
	PagesConfig    = apptypes.PagesConfig
	OAuthConfig    = apptypes.OAuthConfig
	EmailConfig    = apptypes.EmailConfig
	RoleDefinition = apptypes.RoleDefinition
	Hooks          = apptypes.Hooks
	FieldType      = apptypes.FieldType
	ProfileField   = apptypes.ProfileField
	ProfileSchema  = apptypes.ProfileSchema
	ProfileInput   = apptypes.ProfileInput
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
			TTL:         7 * 24 * time.Hour,
			IdleTimeout: 24 * time.Hour,
			MaxLifetime: 30 * 24 * time.Hour,
			CookieName:  "session",
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

func validateProductionPages(c *Config) error {
	for _, pageURL := range []string{c.Pages.SignInURL, c.Pages.ResetPasswordURL, c.Pages.VerifyEmailURL, c.Pages.CallbackURL} {
		if pageURL == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(pageURL))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("page URL must be absolute: %q", pageURL)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("page URL must use https in production: %q", pageURL)
		}
	}
	return nil
}

// ValidateConfigProduction adds extra checks used by example server.
func ValidateConfigProduction(c *Config) error {
	if err := ValidateConfig(c); err != nil {
		return err
	}
	if c.Env != "production" {
		return nil
	}
	return validateProductionPages(c)
}
