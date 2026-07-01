package middleware

import (
	"context"
	"crypto/rand"
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

const csrfCookie = "csrf_token"

func CSRF(enabled bool, allowedOrigins []string) func(next http.Handler) http.Handler {
	if !enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				ensureCSRFCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}
			if isSafeServiceCall(r) {
				next.ServeHTTP(w, r)
				return
			}
			cookie, _ := r.Cookie(csrfCookie)
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

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie(csrfCookie); c != nil && c.Value != "" {
		return
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

func isSafeServiceCall(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("X-Service-Key")) != "" ||
		strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
}
