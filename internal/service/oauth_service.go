package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auth-project/goauth/internal/apptypes"
	"github.com/auth-project/goauth/internal/domain/auth"
	auth_repo "github.com/auth-project/goauth/internal/repository/auth"
	"github.com/google/uuid"
)

const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"
)

var (
	googleAuthURL   = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL  = "https://oauth2.googleapis.com/token"
	googleUserURL   = "https://www.googleapis.com/oauth2/v2/userinfo"
	githubAuthURL   = "https://github.com/login/oauth/authorize"
	githubTokenURL  = "https://github.com/login/oauth/access_token"
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

// OAuthService handles OAuth initiate and callback flows.
type OAuthService struct {
	cfg        *apptypes.AppConfig
	authSvc    *AuthService
	idpSvc     *IdPService
	userRepo   *auth_repo.UserAuthRepo
	oauthRepo  *auth_repo.OAuthAccountRepo
	auditSvc   *AuditService
	httpClient *http.Client
}

func NewOAuthService(cfg *apptypes.AppConfig, authSvc *AuthService, idpSvc *IdPService, userRepo *auth_repo.UserAuthRepo, oauthRepo *auth_repo.OAuthAccountRepo, auditSvc *AuditService) *OAuthService {
	return &OAuthService{
		cfg:        cfg,
		authSvc:    authSvc,
		idpSvc:     idpSvc,
		userRepo:   userRepo,
		oauthRepo:  oauthRepo,
		auditSvc:   auditSvc,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// state = base64(redirectURI) + "." + hex(hmac(redirectURI))
func (s *OAuthService) signState(redirectURI string) string {
	b := base64.URLEncoding.EncodeToString([]byte(redirectURI))
	mac := hmac.New(sha256.New, []byte(s.cfg.Security.SessionSecret))
	mac.Write([]byte(b))
	return b + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *OAuthService) verifyState(state string) (redirectURI string, ok bool) {
	state = strings.TrimSpace(state)
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	parts[0] = strings.TrimSpace(parts[0])
	parts[1] = strings.TrimSpace(parts[1])
	b, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	redirectURI = strings.TrimSpace(string(b))
	mac := hmac.New(sha256.New, []byte(s.cfg.Security.SessionSecret))
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	return redirectURI, hmac.Equal([]byte(parts[1]), []byte(expected))
}

// AuthURL returns the provider authorization URL and state for the given redirect_uri (frontend URL).
func (s *OAuthService) AuthURL(provider, redirectURI, callbackBaseURL string) (authURL string, state string, err error) {
	redirectURI = strings.TrimSpace(redirectURI)
	state = s.signState(redirectURI)
	callbackURL := callbackBaseURL + "/api/v1/auth/oauth/" + provider + "/callback"

	switch provider {
	case ProviderGoogle:
		if s.cfg.OAuth.GoogleClientID == "" {
			return "", "", fmt.Errorf("google oauth not configured")
		}
		u, _ := url.Parse(googleAuthURL)
		q := u.Query()
		q.Set("client_id", s.cfg.OAuth.GoogleClientID)
		q.Set("redirect_uri", callbackURL)
		q.Set("response_type", "code")
		q.Set("scope", "openid email profile")
		q.Set("state", state)
		u.RawQuery = q.Encode()
		return u.String(), state, nil
	case ProviderGitHub:
		if s.cfg.OAuth.GitHubClientID == "" {
			return "", "", fmt.Errorf("github oauth not configured")
		}
		u, _ := url.Parse(githubAuthURL)
		q := u.Query()
		q.Set("client_id", s.cfg.OAuth.GitHubClientID)
		q.Set("redirect_uri", callbackURL)
		q.Set("scope", "user:email read:user")
		q.Set("state", state)
		u.RawQuery = q.Encode()
		return u.String(), state, nil
	default:
		return "", "", fmt.Errorf("unknown provider: %s", provider)
	}
}

// TokenAndUser holds session result for OAuth callback.
type TokenAndUser struct {
	Token     string
	SessionID uuid.UUID
	ExpiresAt time.Time
}

// Callback exchanges code for token, fetches provider user, creates or links account, creates session.
func (s *OAuthService) Callback(ctx context.Context, provider, code, state, callbackBaseURL, ipAddress, userAgent string) (redirectURI string, result *TokenAndUser, err error) {
	redirectURI, ok := s.verifyState(state)
	if !ok {
		return "", nil, fmt.Errorf("invalid state")
	}
	callbackURL := callbackBaseURL + "/api/v1/auth/oauth/" + provider + "/callback"

	var accessToken string
	var providerUserID, email, name, imageURL string

	switch provider {
	case ProviderGoogle:
		accessToken, err = s.exchangeGoogle(ctx, code, callbackURL)
		if err != nil {
			return redirectURI, nil, err
		}
		providerUserID, email, name, imageURL, err = s.fetchGoogleUser(ctx, accessToken)
	case ProviderGitHub:
		accessToken, err = s.exchangeGitHub(ctx, code, callbackURL)
		if err != nil {
			return redirectURI, nil, err
		}
		providerUserID, email, name, imageURL, err = s.fetchGitHubUser(ctx, accessToken)
	default:
		return redirectURI, nil, fmt.Errorf("unknown provider: %s", provider)
	}
	if err != nil {
		return redirectURI, nil, err
	}
	if providerUserID == "" || email == "" {
		return redirectURI, nil, fmt.Errorf("provider did not return user id or email")
	}

	// Find existing OAuth link
	existing, _ := s.oauthRepo.GetByProviderAndAccountID(ctx, provider, providerUserID)
	if existing != nil {
		token, sess, err := s.authSvc.CreateSession(ctx, existing.UserID, ipAddress, userAgent)
		if err != nil {
			return redirectURI, nil, err
		}
		return redirectURI, &TokenAndUser{Token: token, SessionID: sess.ID, ExpiresAt: sess.ExpiresAt}, nil
	}

	// Find existing user by email and link
	user, _ := s.userRepo.GetByEmail(ctx, email)
	if user != nil {
		now := time.Now()
		oa := &auth.OAuthAccount{
			ID:                uuid.New(),
			UserID:            user.ID,
			Provider:          provider,
			ProviderAccountID: providerUserID,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		if err := s.oauthRepo.Create(ctx, oa); err != nil {
			return redirectURI, nil, err
		}
		// Ensure IdP profile exists so GET /account does not 404
		profile, _ := s.idpSvc.GetProfile(ctx, user.ID)
		if profile == nil {
			profileName := name
			if profileName == "" {
				profileName = email
			}
			if err := s.idpSvc.CreateProfile(ctx, user.ID, apptypes.ProfileInput{Name: profileName}); err != nil {
				return redirectURI, nil, err
			}
		}
		if imageURL != "" {
			_ = s.idpSvc.UpdateProfile(ctx, user.ID, apptypes.ProfileInput{ImageURL: imageURL})
		}
		token, sess, err := s.authSvc.CreateSession(ctx, user.ID, ipAddress, userAgent)
		if err != nil {
			return redirectURI, nil, err
		}
		return redirectURI, &TokenAndUser{Token: token, SessionID: sess.ID, ExpiresAt: sess.ExpiresAt}, nil
	}

	// Create new user + profile + oauth link + session
	userID := uuid.New()
	if err := s.authSvc.CreateUserAuth(ctx, userID, email); err != nil {
		return redirectURI, nil, err
	}
	if name == "" {
		name = email
	}
	if err := s.idpSvc.CreateProfile(ctx, userID, apptypes.ProfileInput{Name: name}); err != nil {
		return redirectURI, nil, err
	}
	now := time.Now()
	oa := &auth.OAuthAccount{
		ID:                uuid.New(),
		UserID:            userID,
		Provider:          provider,
		ProviderAccountID: providerUserID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.oauthRepo.Create(ctx, oa); err != nil {
		return redirectURI, nil, err
	}
	// Optionally update profile image from provider
	if imageURL != "" {
		_ = s.idpSvc.UpdateProfile(ctx, userID, apptypes.ProfileInput{ImageURL: imageURL})
	}
	token, sess, err := s.authSvc.CreateSession(ctx, userID, ipAddress, userAgent)
	if err != nil {
		return redirectURI, nil, err
	}
	return redirectURI, &TokenAndUser{Token: token, SessionID: sess.ID, ExpiresAt: sess.ExpiresAt}, nil
}

func (s *OAuthService) exchangeGoogle(ctx context.Context, code, callbackURL string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", s.cfg.OAuth.GoogleClientID)
	data.Set("client_secret", s.cfg.OAuth.GoogleClientSecret)
	data.Set("redirect_uri", callbackURL)
	data.Set("grant_type", "authorization_code")
	req, _ := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google token exchange: %s", string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

func (s *OAuthService) fetchGoogleUser(ctx context.Context, accessToken string) (id, email, name, imageURL string, err error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", googleUserURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", fmt.Errorf("google userinfo: %s", string(body))
	}
	var u struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", "", "", "", err
	}
	return u.ID, u.Email, u.Name, u.Picture, nil
}

func (s *OAuthService) exchangeGitHub(ctx context.Context, code, callbackURL string) (string, error) {
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", s.cfg.OAuth.GitHubClientID)
	data.Set("client_secret", s.cfg.OAuth.GitHubClientSecret)
	data.Set("redirect_uri", callbackURL)
	req, _ := http.NewRequestWithContext(ctx, "POST", githubTokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github token exchange: %s", string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

func (s *OAuthService) fetchGitHubUser(ctx context.Context, accessToken string) (id, email, name, imageURL string, err error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", githubUserURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", fmt.Errorf("github user: %s", string(body))
	}
	var u struct {
		ID      int    `json:"id"`
		Login   string `json:"login"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Avatar  string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", "", "", "", err
	}
	idStr := fmt.Sprintf("%d", u.ID)
	name = u.Name
	if name == "" {
		name = u.Login
	}
	imageURL = u.Avatar
	if u.Email == "" {
		u.Email, _ = s.fetchGitHubPrimaryEmail(ctx, accessToken)
	}
	return idStr, u.Email, name, imageURL, nil
}

func (s *OAuthService) fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", githubEmailsURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github emails: %s", string(body))
	}
	var list []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return "", err
	}
	for _, e := range list {
		if e.Primary {
			return e.Email, nil
		}
	}
	if len(list) > 0 {
		return list[0].Email, nil
	}
	return "", nil
}
