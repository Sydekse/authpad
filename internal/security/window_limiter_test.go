package security

import (
	"context"
	"testing"
	"time"
)

func TestMemoryWindowLimiter(t *testing.T) {
	l := NewMemoryWindowLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !l.Allow(ctx, "k", 3, time.Minute) {
			t.Fatalf("hit %d should be allowed", i+1)
		}
	}
	if l.Allow(ctx, "k", 3, time.Minute) {
		t.Fatal("4th hit should be limited")
	}
	if !l.Allow(ctx, "other", 3, time.Minute) {
		t.Fatal("other key is independent")
	}
	now = now.Add(2 * time.Minute)
	if !l.Allow(ctx, "k", 3, time.Minute) {
		t.Fatal("window should have reset")
	}
	if !l.Allow(ctx, "k", 0, time.Minute) {
		t.Fatal("limit 0 disables limiting")
	}
}
