package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
	"github.com/Sydekse/authpad/internal/database"
	"github.com/Sydekse/authpad/internal/handler"
	"github.com/Sydekse/authpad/internal/middleware"
	auth_repo "github.com/Sydekse/authpad/internal/repository/auth"
	idp_repo "github.com/Sydekse/authpad/internal/repository/idp"
	"github.com/Sydekse/authpad/internal/security"
	"github.com/Sydekse/authpad/internal/service"
	"github.com/go-chi/chi/v5"
)

// Server is the wired auth library instance.
type Server struct {
	cfg        apptypes.AppConfig
	auth       *handler.AuthHandlers
	idp        *handler.IdPHandlers
	oauth      *handler.OAuthHandlers
	admin      *handler.AdminHandlers
	mfa        *handler.MFAHandlers
	invites    *handler.InviteHandlers
	orgs       *handler.OrgHandlers
	authDB     *database.AuthDB
	idpDB      *database.IdPDB
	AuthSvc    *service.AuthService
	AccountSvc *service.AccountService
	IdPSvc     *service.IdPService
	OrgSvc     *service.OrgService
	InviteSvc  *service.InviteService
	Password   *security.PasswordService
}

// New wires dependencies and returns a ready server.
func New(cfg apptypes.AppConfig) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Session.CookieName == "" {
		cfg.Session.CookieName = "session"
	}
	if cfg.Session.TTL == 0 {
		cfg.Session.TTL = 7 * 24 * time.Hour
	}
	if cfg.Security.PasswordPolicy.MinLength == 0 {
		cfg.Security.PasswordPolicy.MinLength = 8
	}
	if cfg.Security.AdminRoleName == "" {
		cfg.Security.AdminRoleName = "admin"
	}
	if cfg.Email.AppName == "" {
		cfg.Email.AppName = cfg.Pages.AppName
	}
	if cfg.APIBasePath == "" {
		cfg.APIBasePath = "/api/v1"
	}
	if cfg.Tenancy.Enabled {
		if cfg.Tenancy.DefaultOrgRole == "" {
			cfg.Tenancy.DefaultOrgRole = "member"
		}
		if len(cfg.Tenancy.OrgRoles) == 0 {
			cfg.Tenancy.OrgRoles = []apptypes.RoleDefinition{
				{Name: "owner", Description: "Organization owner"},
				{Name: "admin", Description: "Organization admin"},
				{Name: "member", Description: "Organization member"},
			}
		}
		if !cfg.Tenancy.AllowCreateOrganization && !cfg.Tenancy.AllowPersonalAccounts && !cfg.Tenancy.RequireOnSignup {
			cfg.Tenancy.AllowCreateOrganization = true
			cfg.Tenancy.AllowPersonalAccounts = true
		}
	}

	ctx := context.Background()
	authDB, err := database.NewAuthDB(ctx, cfg.AuthDatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect auth database: %w", err)
	}

	var idpDB *database.IdPDB
	if cfg.IdPEnabled() {
		idpDB, err = database.NewIdPDB(ctx, cfg.IdPDatabaseURL)
		if err != nil {
			authDB.Close()
			return nil, fmt.Errorf("connect idp database: %w", err)
		}
	}

	passwordSvc, err := security.NewPasswordService(cfg.Security.PepperKey)
	if err != nil {
		authDB.Close()
		if idpDB != nil {
			idpDB.Close()
		}
		return nil, fmt.Errorf("password service: %w", err)
	}

	userAuthRepo := auth_repo.NewUserAuthRepo(authDB)
	credRepo := auth_repo.NewCredentialRepo(authDB)
	sessionRepo := auth_repo.NewSessionRepo(authDB)
	resetTokenRepo := auth_repo.NewPasswordResetTokenRepo(authDB)
	oauthRepo := auth_repo.NewOAuthAccountRepo(authDB)
	auditRepo := auth_repo.NewAuditRepo(authDB)
	verifyRepo := auth_repo.NewEmailVerificationRepo(authDB)
	factorRepo := auth_repo.NewFactorRepo(authDB)

	authSvc := service.NewAuthService(
		userAuthRepo, credRepo, sessionRepo, resetTokenRepo, verifyRepo, factorRepo,
		passwordSvc, cfg.Session, cfg.Security.PasswordPolicy, cfg.Email.RequireVerification,
	)
	auditSvc := service.NewAuditService(auditRepo, nil)

	var idpSvc *service.IdPService
	if idpDB != nil {
		profileRepo := idp_repo.NewProfileRepo(idpDB)
		roleRepo := idp_repo.NewRoleRepo(idpDB)
		groupRepo := idp_repo.NewGroupRepo(idpDB)
		idpAuditRepo := idp_repo.NewAuditRepo(idpDB)
		idpSvc = service.NewIdPService(profileRepo, roleRepo, groupRepo, idpAuditRepo, cfg.Roles, cfg.Hooks.OnRoleAssigned)
		auditSvc = service.NewAuditService(auditRepo, idpAuditRepo)
		if err := idpSvc.SeedRoles(ctx); err != nil {
			authDB.Close()
			idpDB.Close()
			return nil, fmt.Errorf("seed roles: %w", err)
		}
	}

	accountSvc := service.NewAccountService(authSvc, idpSvc, userAuthRepo, credRepo, auditSvc, cfg.ProfileSchema, cfg.Hooks)
	emailSvc := service.NewEmailService(cfg.Email, cfg.Pages)
	var mailer apptypes.Mailer = emailSvc
	if cfg.Mailer != nil {
		mailer = cfg.Mailer
	}
	oauthStateRepo := auth_repo.NewOAuthStateRepo(authDB)
	mfaSvc := service.NewMFAService(factorRepo, authSvc, auditSvc, cfg.Security.SessionSecret, mfaIssuer(cfg))

	var inviteSvc *service.InviteService
	var orgSvc *service.OrgService
	if idpDB != nil {
		inviteRepo := idp_repo.NewInvitationRepo(idpDB)
		inviteSvc = service.NewInviteService(inviteRepo, accountSvc, idpSvc, &cfg)
		orgRepo := idp_repo.NewOrgRepo(idpDB)
		orgSvc = service.NewOrgService(orgRepo, &cfg, authSvc)
	}
	oauthSvc := service.NewOAuthService(&cfg, authSvc, idpSvc, mfaSvc, userAuthRepo, oauthRepo, oauthStateRepo, auditSvc, orgSvc)

	srv := &Server{
		cfg:        cfg,
		authDB:     authDB,
		idpDB:      idpDB,
		AuthSvc:    authSvc,
		AccountSvc: accountSvc,
		IdPSvc:     idpSvc,
		OrgSvc:     orgSvc,
		InviteSvc:  inviteSvc,
		Password:   passwordSvc,
		auth: &handler.AuthHandlers{
			Account: accountSvc,
			Auth:    authSvc,
			IdP:     idpSvc,
			MFA:     mfaSvc,
			Email:   mailer,
			Audit:   auditSvc,
			Orgs:    orgSvc,
			Cfg:     &cfg,
		},
		idp: &handler.IdPHandlers{
			Auth:    authSvc,
			IdP:     idpSvc,
			Account: accountSvc,
			Audit:   auditSvc,
			Orgs:    orgSvc,
			Cfg:     &cfg,
		},
		oauth: &handler.OAuthHandlers{OAuth: oauthSvc, Cfg: &cfg},
		admin: &handler.AdminHandlers{IdP: idpSvc, Auth: authSvc, Audit: auditSvc, Cfg: &cfg},
		mfa:   &handler.MFAHandlers{MFA: mfaSvc, Auth: authSvc, Cfg: &cfg},
	}
	if inviteSvc != nil {
		srv.invites = &handler.InviteHandlers{Invites: inviteSvc, Email: mailer, Auth: authSvc, IdP: idpSvc, Cfg: &cfg}
	}
	if orgSvc != nil {
		srv.orgs = &handler.OrgHandlers{Orgs: orgSvc, Auth: authSvc, Email: mailer, Cfg: &cfg}
	}
	return srv, nil
}

// Close releases database connections.
func (s *Server) Close() {
	if s.authDB != nil {
		s.authDB.Close()
	}
	if s.idpDB != nil {
		s.idpDB.Close()
	}
}

// Ready checks database connectivity.
func (s *Server) Ready(ctx context.Context) error {
	if s.authDB != nil {
		if err := s.authDB.Ping(ctx); err != nil {
			return err
		}
	}
	if s.idpDB != nil {
		if err := s.idpDB.Ping(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Mount registers routes on a chi router.
func (s *Server) Mount(r chi.Router, basePath string) {
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		basePath = "/api/v1"
	}
	if s.auth != nil && s.auth.Cfg != nil {
		s.auth.Cfg.APIBasePath = basePath
	}

	rateLimit := middleware.RateLimiter(s.cfg.Security.RateLimitRPM, s.cfg.Security.RateLimitBurst, s.cfg.Security.RedisURL)
	csrf := middleware.CSRF(middleware.CSRFConfig{
		Enabled:           s.cfg.Security.CSRFEnabled,
		ServiceKeys:       s.cfg.Security.ServiceKeys,
		SessionCookieName: s.cfg.Session.CookieName,
		ValidateBearer: func(r *http.Request, token string) bool {
			sess, err := s.AuthSvc.GetSessionByToken(r.Context(), token)
			return err == nil && sess != nil && !sess.MFAPending
		},
	})

	r.Route(basePath, func(r chi.Router) {
		if !s.cfg.DisablePublicSignup && !s.skipPath("/auth/signup") {
			r.With(rateLimit).Post("/auth/signup", s.auth.Signup)
		}
		if !s.skipPath("/auth/login") {
			r.With(rateLimit, csrf).Post("/auth/login", s.auth.Login)
		}
		r.With(csrf).Post("/auth/logout", s.auth.Logout)
		r.With(csrf).Post("/auth/logout-all", s.auth.LogoutAll)
		r.Get("/auth/session", s.auth.Session)
		r.With(rateLimit).Get("/auth/verify-email", s.auth.VerifyEmail)
		r.With(rateLimit, csrf).Post("/auth/verify-email/resend", s.auth.ResendVerification)
		r.With(rateLimit).Get("/auth/oauth/{provider}", s.oauth.OAuthInit)
		r.With(rateLimit).Get("/auth/oauth/{provider}/callback", s.oauth.OAuthCallback)
		r.With(rateLimit, csrf).Post("/auth/password/reset-request", s.auth.PasswordResetRequest)
		r.With(rateLimit, csrf).Post("/auth/password/reset", s.auth.PasswordReset)

		r.Get("/auth/mfa", s.mfa.ListFactors)
		r.With(csrf).Post("/auth/mfa/enroll", s.mfa.EnrollTOTP)
		r.With(csrf).Post("/auth/mfa/verify", s.mfa.VerifyTOTP)
		r.With(rateLimit, csrf).Post("/auth/mfa/challenge", s.mfa.Challenge)
		r.With(csrf).Post("/auth/mfa/webauthn/register/begin", s.mfa.WebAuthnRegisterBegin)
		r.With(csrf).Post("/auth/mfa/webauthn/register/finish", s.mfa.WebAuthnRegisterFinish)
		r.With(csrf).Delete("/auth/mfa/{id}", s.mfa.DeleteFactor)

		if s.idp != nil && s.idp.IdP != nil {
			r.Get("/idp/userinfo", s.idp.Userinfo)
			r.Get("/idp/users/{id}", s.idp.GetUserByID)
			r.Get("/idp/users/{id}/roles", s.idp.GetUserRoles)
			r.Get("/idp/users/{id}/groups", s.idp.GetUserGroups)

			r.Get("/account", s.idp.GetAccount)
			r.Get("/account/complete", s.idp.GetAccountComplete)
			r.With(csrf).Patch("/account", s.idp.PatchAccount)
			r.With(csrf).Post("/account/role", s.idp.AssignRole)
			r.Get("/account/sessions", s.idp.ListSessions)
			r.With(csrf).Delete("/account/sessions/{id}", s.idp.RevokeSession)
			r.Get("/account/audit", s.idp.GetAccountAudit)
			r.Get("/account/export", s.idp.ExportAccount)
			r.With(csrf).Delete("/account", s.idp.DeleteAccount)

			if !s.skipPath("/admin/roles") {
				r.Get("/admin/roles", s.admin.ListRoles)
				r.With(csrf).Post("/admin/roles", s.admin.CreateRole)
			}
			r.With(csrf).Post("/admin/roles/assign", s.admin.AssignRole)
			r.With(csrf).Post("/admin/roles/revoke", s.admin.RevokeRole)
			r.With(csrf).Post("/admin/groups", s.admin.CreateGroup)
			r.With(csrf).Post("/admin/groups/{id}/members", s.admin.AddGroupMember)
			r.With(csrf).Delete("/admin/groups/{id}/members/{userId}", s.admin.RemoveGroupMember)
			r.Get("/admin/audit", s.admin.GetAuditLogs)
		}

		if s.cfg.Invitations.Enabled && s.invites != nil && !s.skipPath("/admin/invitations") {
			r.With(rateLimit).Get("/invitations/{token}/validate", s.invites.Validate)
			r.With(csrf).Post("/admin/invitations", s.invites.Create)
			r.Get("/admin/invitations", s.invites.List)
			r.With(csrf).Delete("/admin/invitations/{id}", s.invites.Revoke)
			if !s.skipPath("/auth/signup/invite") {
				r.With(rateLimit, csrf).Post("/auth/signup/invite", s.invites.Redeem)
			}
		}

		if s.cfg.Tenancy.Enabled && s.orgs != nil && !s.skipPath("/organizations") {
			r.With(rateLimit).Get("/organizations/invitations/{token}/validate", s.orgs.ValidateInvite)
			r.With(csrf).Post("/organizations", s.orgs.Create)
			r.Get("/organizations", s.orgs.List)
			r.Get("/organizations/{slug}", s.orgs.Get)
			r.With(csrf).Patch("/organizations/{slug}", s.orgs.Patch)
			r.Get("/organizations/{slug}/members", s.orgs.Members)
			r.Get("/organizations/{slug}/roles", s.orgs.ListRoles)
			r.With(csrf).Post("/organizations/{slug}/roles", s.orgs.CreateRole)
			r.Get("/organizations/{slug}/departments", s.orgs.ListDepartments)
			r.With(csrf).Post("/organizations/{slug}/departments", s.orgs.CreateDepartment)
			r.With(csrf).Delete("/organizations/{slug}/departments/{id}", s.orgs.DeleteDepartment)
			r.Get("/organizations/{slug}/levels", s.orgs.ListLevels)
			r.With(csrf).Post("/organizations/{slug}/levels", s.orgs.CreateLevel)
			r.With(csrf).Delete("/organizations/{slug}/levels/{id}", s.orgs.DeleteLevel)
			r.Get("/organizations/{slug}/invitations", s.orgs.ListInvitations)
			r.With(csrf).Post("/organizations/{slug}/invitations", s.orgs.Invite)
			r.With(csrf).Delete("/organizations/{slug}/invitations/{id}", s.orgs.RevokeInvite)
			r.With(csrf).Post("/organizations/invitations/accept", s.orgs.AcceptInvite)
			r.With(csrf).Post("/session/organization", s.orgs.Switch)
		}
	})
}

func (s *Server) skipPath(path string) bool {
	want := strings.TrimSuffix(strings.TrimSpace(path), "/")
	for _, p := range s.cfg.SkipHTTPPaths {
		if strings.TrimSuffix(strings.TrimSpace(p), "/") == want {
			return true
		}
	}
	return false
}

func (s *Server) AuthHandlersCfg() *apptypes.AppConfig {
	if s.auth != nil && s.auth.Cfg != nil {
		return s.auth.Cfg
	}
	return &s.cfg
}

func mfaIssuer(cfg apptypes.AppConfig) string {
	if name := strings.TrimSpace(cfg.Pages.AppName); name != "" {
		return name
	}
	if name := strings.TrimSpace(cfg.Email.AppName); name != "" {
		return name
	}
	return "Auth"
}
