package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFRejectsBearerHeaderBypass(t *testing.T) {
	h := CSRF(CSRFConfig{Enabled: true, SessionCookieName: "session"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set("Authorization", "Bearer totally-fake")
	req.AddCookie(&http.Cookie{Name: "session", Value: "cookie-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cookie session with dummy bearer must still require CSRF, got %d", rec.Code)
	}
}

func TestCSRFRejectsUnvalidatedServiceKey(t *testing.T) {
	h := CSRF(CSRFConfig{Enabled: true, ServiceKeys: map[string]string{"default": "real-key"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-Service-Key", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid service key must not bypass CSRF, got %d", rec.Code)
	}
}

func TestCSRFAllowsValidatedServiceKey(t *testing.T) {
	h := CSRF(CSRFConfig{Enabled: true, ServiceKeys: map[string]string{"default": "real-key"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-Service-Key", "real-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid service key should bypass CSRF, got %d", rec.Code)
	}
}

func TestCSRFAllowsBearerOnlyWhenValidated(t *testing.T) {
	h := CSRF(CSRFConfig{
		Enabled:           true,
		SessionCookieName: "session",
		ValidateBearer: func(r *http.Request, token string) bool {
			return token == "good"
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	bad := httptest.NewRequest(http.MethodPost, "/x", nil)
	bad.Header.Set("Authorization", "Bearer bad")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid bearer-only request must require CSRF, got %d", rec.Code)
	}

	good := httptest.NewRequest(http.MethodPost, "/x", nil)
	good.Header.Set("Authorization", "Bearer good")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, good)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("validated bearer-only request should bypass CSRF, got %d", rec.Code)
	}
}

func TestCSRFAcceptsMatchingCookieHeader(t *testing.T) {
	h := CSRF(CSRFConfig{Enabled: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "abc"})
	req.Header.Set("X-CSRF-Token", "abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("matching CSRF cookie+header should pass, got %d", rec.Code)
	}
}
