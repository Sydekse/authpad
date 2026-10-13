package security

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// WindowLimiter is a fixed-window counter keyed by an arbitrary string.
// Allow records one hit and reports whether it is within limit for the window.
type WindowLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) bool
}

// MemoryWindowLimiter is an in-process WindowLimiter.
type MemoryWindowLimiter struct {
	mu      sync.Mutex
	entries map[string]*windowEntry
	now     func() time.Time
	sweepAt time.Time
}

type windowEntry struct {
	count int
	reset time.Time
}

func NewMemoryWindowLimiter() *MemoryWindowLimiter {
	return &MemoryWindowLimiter{entries: map[string]*windowEntry{}, now: time.Now}
}

func (l *MemoryWindowLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.After(l.sweepAt) {
		for k, e := range l.entries {
			if now.After(e.reset) {
				delete(l.entries, k)
			}
		}
		l.sweepAt = now.Add(window)
	}
	e := l.entries[key]
	if e == nil || now.After(e.reset) {
		e = &windowEntry{reset: now.Add(window)}
		l.entries[key] = e
	}
	e.count++
	return e.count <= limit
}

// RedisWindowLimiter shares counters across processes. It fails open on Redis
// errors, matching the HTTP rate limiter.
type RedisWindowLimiter struct {
	client *redis.Client
}

// NewRedisWindowLimiter returns nil when redisURL cannot be parsed.
func NewRedisWindowLimiter(redisURL string) *RedisWindowLimiter {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil
	}
	return &RedisWindowLimiter{client: redis.NewClient(opt)}
}

func (l *RedisWindowLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	k := "ratelimit:" + key
	n, err := l.client.Incr(ctx, k).Result()
	if err != nil {
		return true
	}
	if n == 1 {
		_ = l.client.Expire(ctx, k, window).Err()
	}
	return n <= int64(limit)
}
