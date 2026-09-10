package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

func clientIP(r *http.Request) string {
	raw := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		raw = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		if net.ParseIP(raw) != nil {
			return raw
		}
		return ""
	}
	return host
}

type limiterEntry struct {
	lim      *rate.Limiter
	lastUsed int64
}

func RateLimiter(requestsPerMinute, burst int, redisURL string) func(next http.Handler) http.Handler {
	if requestsPerMinute <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	if redisURL != "" {
		return redisRateLimiter(requestsPerMinute, burst, redisURL)
	}
	limit := rate.Every(time.Minute / time.Duration(requestsPerMinute))
	m := &sync.Map{}
	go func() {
		tick := time.NewTicker(10 * time.Minute)
		defer tick.Stop()
		for range tick.C {
			now := time.Now().Unix()
			m.Range(func(key, value interface{}) bool {
				ent := value.(*limiterEntry)
				if now-atomic.LoadInt64(&ent.lastUsed) > 600 {
					m.Delete(key)
				}
				return true
			})
		}
	}()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if ip == "" {
				next.ServeHTTP(w, r)
				return
			}
			var ent *limiterEntry
			if v, ok := m.Load(ip); ok {
				ent = v.(*limiterEntry)
			} else {
				ent = &limiterEntry{lim: rate.NewLimiter(limit, burst)}
				if v, loaded := m.LoadOrStore(ip, ent); loaded {
					ent = v.(*limiterEntry)
				}
			}
			atomic.StoreInt64(&ent.lastUsed, time.Now().Unix())
			if !ent.lim.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"Too many requests"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func redisRateLimiter(requestsPerMinute, burst int, redisURL string) func(next http.Handler) http.Handler {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return RateLimiter(requestsPerMinute, burst, "")
	}
	client := redis.NewClient(opt)
	window := time.Minute
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if ip == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := "ratelimit:" + ip
			ctx := context.Background()
			count, err := client.Incr(ctx, key).Result()
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if count == 1 {
				_ = client.Expire(ctx, key, window).Err()
			}
			if count > int64(requestsPerMinute)+int64(burst) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"Too many requests"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

const CSRFCookieName = "csrf_token"

// CSRFConfig controls double-submit CSRF enforcement.
type CSRFConfig struct {
	Enabled           bool
	ServiceKeys       map[string]string
	SessionCookieName string
	// ValidateBearer is consulted only when Authorization Bearer is present
	// AND the session cookie is absent. Cookie sessions always require CSRF.
	ValidateBearer func(r *http.Request, token string) bool
}

func CSRF(cfg CSRFConfig) func(next http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	cookieName := cfg.SessionCookieName
	if cookieName == "" {
		cookieName = "session"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				EnsureCSRFCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}
			if isValidatedServiceKey(r, cfg.ServiceKeys) {
				next.ServeHTTP(w, r)
				return
			}
			if isValidatedBearerOnly(r, cookieName, cfg.ValidateBearer) {
				next.ServeHTTP(w, r)
				return
			}
			cookie, _ := r.Cookie(CSRFCookieName)
			header := r.Header.Get("X-CSRF-Token")
			if cookie == nil || header == "" || cookie.Value != header {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"CSRF_INVALID","message":"Invalid CSRF token"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// EnsureCSRFCookie issues a csrf_token cookie if one is not already present
// and returns the token value.
func EnsureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, _ := r.Cookie(CSRFCookieName); c != nil && c.Value != "" {
		return c.Value
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func isValidatedServiceKey(r *http.Request, keys map[string]string) bool {
	provided := strings.TrimSpace(r.Header.Get("X-Service-Key"))
	if provided == "" || len(keys) == 0 {
		return false
	}
	providedB := []byte(provided)
	for _, allowed := range keys {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if subtle.ConstantTimeCompare(providedB, []byte(allowed)) == 1 {
			return true
		}
	}
	return false
}

func isValidatedBearerOnly(r *http.Request, sessionCookieName string, validate func(*http.Request, string) bool) bool {
	if validate == nil {
		return false
	}
	if c, _ := r.Cookie(sessionCookieName); c != nil && strings.TrimSpace(c.Value) != "" {
		return false
	}
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return false
	}
	token := strings.TrimSpace(h[7:])
	if token == "" {
		return false
	}
	return validate(r, token)
}
