package service

import (
	"testing"

	"github.com/Sydekse/authpad/internal/apptypes"
)

func TestNormalizeSlug(t *testing.T) {
	if got := NormalizeSlug("Acme Corp"); got != "acme-corp" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeSlug("  Hello!!  "); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestFilterOrgPrivateMetadata(t *testing.T) {
	cfg := &apptypes.AppConfig{}
	cfg.Tenancy.Enabled = true
	cfg.Tenancy.OrgPrivateMetadataKeys = []string{"tin_number"}
	meta := map[string]any{"name": "kept", "tin_number": "secret"}
	got := FilterOrgPrivateMetadata(cfg, meta, false)
	if _, ok := got["tin_number"]; ok {
		t.Fatal("org-private field should be stripped without an active org")
	}
	if got["name"] != "kept" {
		t.Fatal("global field should remain")
	}
	got = FilterOrgPrivateMetadata(cfg, meta, true)
	if got["tin_number"] != "secret" {
		t.Fatal("org-private field should remain when an org is active")
	}
}
