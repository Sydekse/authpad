package auth

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() Config {
	cfg := DefaultConfig()
	cfg.Port = getEnv("PORT", "8080")
	cfg.Env = getEnv("ENV", "development")
	cfg.AuthDatabaseURL = os.Getenv("AUTH_DATABASE_URL")
	cfg.IdPDatabaseURL = os.Getenv("IDP_DATABASE_URL")

	cfg.Session.CookieDomain = getEnv("COOKIE_DOMAIN", "")
	cfg.Session.CookieSecure = os.Getenv("COOKIE_SECURE") == "true" || cfg.Env == "production"
	cfg.Session.TTL = getEnvDuration("SESSION_TTL", 7*24*time.Hour)
	cfg.Session.IdleTimeout = getEnvDuration("SESSION_IDLE_TIMEOUT", 24*time.Hour)
	cfg.Session.MaxLifetime = getEnvDuration("SESSION_MAX_LIFETIME", 30*24*time.Hour)
	cfg.Session.RememberMeTTL = getEnvDuration("SESSION_REMEMBER_TTL", 30*24*time.Hour)

	cfg.Security.PepperKey = os.Getenv("PEPPER_KEY")
	cfg.Security.SessionSecret = os.Getenv("SESSION_SECRET")
	cfg.Security.RedisURL = getEnv("REDIS_URL", "")
	cfg.Security.RateLimitRPM = getEnvInt("RATE_LIMIT_RPM", 15)
	cfg.Security.RateLimitBurst = getEnvInt("RATE_LIMIT_BURST", 5)
	cfg.Security.CSRFEnabled = os.Getenv("CSRF_ENABLED") != "false"
	cfg.Security.AdminRoleName = getEnv("ADMIN_ROLE_NAME", "admin")
	cfg.Security.PasswordPolicy.MinLength = getEnvInt("PASSWORD_MIN_LENGTH", 8)

	cfg.OAuth.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.OAuth.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	cfg.OAuth.GitHubClientID = os.Getenv("GITHUB_CLIENT_ID")
	cfg.OAuth.GitHubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")

	cfg.Email.ResendAPIKey = os.Getenv("RESEND_API_KEY")
	cfg.Email.ResendFrom = os.Getenv("RESEND_FROM")
	cfg.Email.RequireVerification = os.Getenv("REQUIRE_EMAIL_VERIFICATION") == "true"
	cfg.Email.AppName = getEnv("APP_NAME", "Auth")

	cfg.Pages.SignInURL = os.Getenv("SIGN_IN_URL")
	cfg.Pages.SignUpURL = os.Getenv("SIGN_UP_URL")
	cfg.Pages.VerifyEmailURL = os.Getenv("VERIFY_EMAIL_URL")
	cfg.Pages.ResetPasswordURL = os.Getenv("RESET_PASSWORD_URL")
	cfg.Pages.CallbackURL = os.Getenv("CALLBACK_URL")
	cfg.Pages.ErrorURL = os.Getenv("ERROR_URL")
	cfg.Pages.AppName = getEnv("APP_NAME", "Auth")

	if cfg.Pages.ResetPasswordURL == "" {
		cfg.Pages.ResetPasswordURL = os.Getenv("AUTH_APP_URL")
	}

	origins := os.Getenv("ALLOWED_ORIGINS")
	if origins == "" {
		origins = "http://localhost:3000,http://localhost:3001"
	}
	cfg.AllowedOrigins = strings.Split(origins, ",")

	if roles := os.Getenv("ROLES"); roles != "" {
		for _, name := range strings.Split(roles, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.Roles = append(cfg.Roles, RoleDefinition{Name: name})
			}
		}
	}
	if len(cfg.Roles) == 0 {
		cfg.Roles = []RoleDefinition{
			{Name: "admin", Description: "Administrator"},
			{Name: "member", Description: "Default member"},
		}
	}

	if serviceKey := os.Getenv("SERVICE_KEY"); serviceKey != "" {
		cfg.Security.ServiceKeys = map[string]string{"default": serviceKey}
	}

	return cfg
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}
