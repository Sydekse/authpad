package server

import (
	"context"
	"fmt"
	"time"

	"github.com/auth-project/goauth/internal/database"
	"github.com/auth-project/goauth/internal/handler"
	"github.com/auth-project/goauth/internal/middleware"
	auth_repo "github.com/auth-project/goauth/internal/repository/auth"
	idp_repo "github.com/auth-project/goauth/internal/repository/idp"
	"github.com/auth-project/goauth/internal/security"
	"github.com/auth-project/goauth/internal/service"
	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/go-chi/chi/v5"
)

// Server is the wired auth library instance.
type Server struct {
	cfg   apptypes.AppConfig
	auth  *handler.AuthHandlers
	idp   *handler.IdPHandlers
	oauth *handler.OAuthHandlers
	admin *handler.AdminHandlers
	mfa   *handler.MFAHandlers
	authDB *database.AuthDB
	idpDB  *database.IdPDB
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
	oauthSvc := service.NewOAuthService(&cfg, authSvc, idpSvc, userAuthRepo, oauthRepo, auditSvc)
	mfaSvc := service.NewMFAService(factorRepo, authSvc, auditSvc, cfg.Security.SessionSecret)

	return &Server{
		cfg:   cfg,
		authDB: authDB,
		idpDB:  idpDB,
		auth: &handler.AuthHandlers{
			Account: accountSvc,
			Auth:    authSvc,
			IdP:     idpSvc,
			Email:   emailSvc,
			Audit:   auditSvc,
			Cfg:     &cfg,
		},
		idp: &handler.IdPHandlers{
			Auth:    authSvc,
			IdP:     idpSvc,
			Account: accountSvc,
			Audit:   auditSvc,
			Cfg:     &cfg,
		},
		oauth: &handler.OAuthHandlers{OAuth: oauthSvc, Cfg: &cfg},
		admin: &handler.AdminHandlers{IdP: idpSvc, Auth: authSvc, Audit: auditSvc, Cfg: &cfg},
		mfa:   &handler.MFAHandlers{MFA: mfaSvc, Auth: authSvc, Cfg: &cfg},
	}, nil
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
	rateLimit := middleware.RateLimiter(s.cfg.Security.RateLimitRPM, s.cfg.Security.RateLimitBurst, s.cfg.Security.RedisURL)
	csrf := middleware.CSRF(s.cfg.Security.CSRFEnabled, s.cfg.AllowedOrigins)

	r.Route(basePath, func(r chi.Router) {
		r.With(rateLimit).Post("/auth/signup", s.auth.Signup)
		r.With(rateLimit, csrf).Post("/auth/login", s.auth.Login)
		r.With(csrf).Post("/auth/logout", s.auth.Logout)
		r.With(csrf).Post("/auth/logout-all", s.auth.LogoutAll)
		r.Get("/auth/session", s.auth.Session)
		r.With(rateLimit).Get("/auth/verify-email", s.auth.VerifyEmail)
		r.With(rateLimit).Get("/auth/oauth/{provider}", s.oauth.OAuthInit)
		r.With(rateLimit).Get("/auth/oauth/{provider}/callback", s.oauth.OAuthCallback)
		r.With(rateLimit, csrf).Post("/auth/password/reset-request", s.auth.PasswordResetRequest)
		r.With(rateLimit, csrf).Post("/auth/password/reset", s.auth.PasswordReset)

		r.With(csrf).Post("/auth/mfa/enroll", s.mfa.EnrollTOTP)
		r.With(csrf).Post("/auth/mfa/verify", s.mfa.VerifyTOTP)
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

			r.With(csrf).Post("/admin/roles/assign", s.admin.AssignRole)
			r.With(csrf).Post("/admin/roles/revoke", s.admin.RevokeRole)
			r.With(csrf).Post("/admin/groups", s.admin.CreateGroup)
			r.With(csrf).Post("/admin/groups/{id}/members", s.admin.AddGroupMember)
			r.With(csrf).Delete("/admin/groups/{id}/members/{userId}", s.admin.RemoveGroupMember)
			r.Get("/admin/audit", s.admin.GetAuditLogs)
		}
	})
}
