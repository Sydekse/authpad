package service

import (
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
)

func TestSessionIdleLimit(t *testing.T) {
	cfg := apptypes.SessionConfig{
		IdleTimeout:      24 * time.Hour,
		StaffIdleTimeout: 30 * time.Minute,
	}
	if got := sessionIdleLimit(cfg, false, false); got != 24*time.Hour {
		t.Fatalf("member idle: got %s", got)
	}
	if got := sessionIdleLimit(cfg, false, true); got != 0 {
		t.Fatalf("remember-me should skip idle, got %s", got)
	}
	if got := sessionIdleLimit(cfg, true, false); got != 30*time.Minute {
		t.Fatalf("staff idle: got %s", got)
	}
	if got := sessionIdleLimit(cfg, true, true); got != 30*time.Minute {
		t.Fatalf("staff remember-me should still idle, got %s", got)
	}
	cfg.StaffIdleTimeout = 0
	if got := sessionIdleLimit(cfg, true, false); got != 24*time.Hour {
		t.Fatalf("staff with feature off should use normal idle, got %s", got)
	}
}
