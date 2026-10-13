package apptypes

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type SessionConfig struct {
	TTL         time.Duration
	IdleTimeout time.Duration
	// StaffIdleTimeout replaces IdleTimeout for sessions marked staff.
	// Zero keeps the normal idle timeout. Staff sessions still idle out when remember-me is on.
	StaffIdleTimeout time.Duration
	MaxLifetime      time.Duration
	RotateInterval   time.Duration
	// RememberMeTTL is used when the client requests "remember me" on login.
	RememberMeTTL time.Duration
	CookieDomain  string
	CookieSecure  bool
	CookieName    string
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

// MagicLinkMailer delivers passwordless sign-in links. It is separate from
// Mailer so existing host implementations of Mailer keep compiling.
type MagicLinkMailer interface {
	SendMagicLink(ctx context.Context, to, linkURL string) error
}

// MagicLinkConfig controls passwordless sign-in for attendees. Off by default.
type MagicLinkConfig struct {
	Enabled bool
	// BaseURL is the public origin of this API (for example https://api.example.com).
	// Links are BaseURL + APIBasePath + /magic-link/verify?token=...
	BaseURL string
	// From is the sender address; falls back to Email.ResendFrom.
	From string
	// RedirectAllowlist holds exact origins (scheme://host[:port]) that
	// redirect_to may point at.
	RedirectAllowlist []string
	// DefaultRedirectURL is used when redirect_to is absent or not allowed;
	// falls back to Pages.CallbackURL.
	DefaultRedirectURL string
	TTL                time.Duration
	EmailLimit         int
	IPLimit            int
	LimitWindow        time.Duration
	// CodeFlow makes verify hand the session over with a one-time code in the
	// redirect instead of an authpad cookie, for apps on another registrable
	// domain. The app redeems the code server-to-server at POST /magic-link/exchange.
	CodeFlow bool
	// ExchangeSecret authenticates POST /magic-link/exchange (header
	// X-Authpad-Exchange-Secret). Empty disables the endpoint.
	ExchangeSecret string
	// ExchangeLimit is the per-IP exchange attempts per minute (0 disables).
	ExchangeLimit int
	// Mailer overrides the built-in Resend / dev-log mailer (tests, hosts).
	Mailer MagicLinkMailer
}

type RoleDefinition struct {
	Name        string
	Description string
}

type Mailer interface {
	SendPasswordReset(to, resetURL string) error
	SendEmailVerification(to, verifyURL string) error
	SendInvitation(to, inviteURL, role string) error
}

type Hooks struct {
	OnRoleAssigned func(ctx context.Context, userID uuid.UUID, role string) error
	OnSignup       func(ctx context.Context, userID uuid.UUID, email string) error
	OnLogin        func(ctx context.Context, userID uuid.UUID) error
	OnDelete       func(ctx context.Context, userID uuid.UUID) error
	// OnOAuthSignup fires after an OAuth callback provisions a session. isNewUser
	// is true when the callback created a brand-new account, and false when it
	// linked a provider to a pre-existing account. Hosts use it to apply the same
	// defaults (role, account_type, onboarding_status) that password signup does,
	// since the OAuth flow bypasses the signup handler and OnSignup hook.
	OnOAuthSignup func(ctx context.Context, userID uuid.UUID, email string, isNewUser bool) error
	// ValidateReturnURL, when set, is the authority for OAuth and post-auth return URLs.
	ValidateReturnURL func(raw string) bool
	// AssignmentPolicy is consulted for role assign/revoke (including self-assign).
	// Return a non-nil error to deny the operation.
	AssignmentPolicy func(ctx context.Context, actor, target uuid.UUID, role, op string) error
	// InvitePolicy is consulted before issuing a generic invitation.
	InvitePolicy func(ctx context.Context, actor uuid.UUID, email, role string) error
	// OrgInvitePolicy is consulted before issuing an organization invitation.
	// Return a non-nil error to deny the operation. Hosts use it for per-org
	// hierarchies (for example only the Sydek org owner may invite admin).
	OrgInvitePolicy func(ctx context.Context, actor uuid.UUID, orgSlug, email, role string) error
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
	// APIBasePath is the mount prefix used to build OAuth provider callback URLs.
	// Mount() overwrites this with the path it is given. Default /api/v1.
	APIBasePath string
	// DisablePublicSignup skips mounting authpad's default POST /auth/signup so a
	// host application (e.g. Sydek auth-api) can register its own restricted handler.
	DisablePublicSignup bool
	// InviteOnlyRoles cannot be self-assigned via POST /account/role.
	InviteOnlyRoles []string
	Mailer          Mailer
	Invitations     InvitationConfig
	MagicLink       MagicLinkConfig
	Tenancy         TenancyConfig
	// SkipHTTPPaths are mount-relative routes authpad will not register
	// (for example "/admin/roles") so a host can provide them itself.
	SkipHTTPPaths []string
}

type InvitationConfig struct {
	Enabled bool
	TTL     time.Duration
}

type TenancyConfig struct {
	Enabled                 bool
	AllowPersonalAccounts   bool
	AllowCreateOrganization bool
	RequireOnSignup         bool
	MaxMembershipsPerUser   int
	DefaultOrgRole          string
	OrgRoles                []RoleDefinition
	// StaffOrgRoles are organization roles that receive StaffIdleTimeout.
	// Empty defaults to owner and admin. The global admin role is always staff.
	StaffOrgRoles []string
	// OrgPrivateMetadataKeys are profile metadata fields that must not be
	// returned unless the request has an active organization.
	OrgPrivateMetadataKeys []string
}

func (c AppConfig) IdPEnabled() bool {
	return c.IdPDatabaseURL != ""
}
