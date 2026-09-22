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

func TestMemberRoleDecision(t *testing.T) {
	if err := memberRoleDecision("owner", "member", "support", 1); err != nil {
		t.Fatalf("owner should change a member: %v", err)
	}
	if err := memberRoleDecision("admin", "member", "support", 1); err != nil {
		t.Fatalf("admin should change a member: %v", err)
	}
	if err := memberRoleDecision("admin", "member", "admin", 2); err != ErrOrgForbidden {
		t.Fatalf("admin must not assign admin, got %v", err)
	}
	if err := memberRoleDecision("admin", "owner", "member", 2); err != ErrOrgForbidden {
		t.Fatalf("admin must not change an owner, got %v", err)
	}
	if err := memberRoleDecision("owner", "member", "owner", 1); err != ErrOrgRoleReserved {
		t.Fatalf("owner role is reserved, got %v", err)
	}
	if err := memberRoleDecision("owner", "owner", "admin", 1); err != ErrLastOwner {
		t.Fatalf("last owner must stay, got %v", err)
	}
	if err := memberRoleDecision("owner", "owner", "", 1); err != ErrLastOwner {
		t.Fatalf("last owner must not be removed, got %v", err)
	}
	if err := memberRoleDecision("owner", "owner", "admin", 2); err != nil {
		t.Fatalf("another owner can demote an owner: %v", err)
	}
	if err := memberRoleDecision("member", "member", "support", 1); err != ErrOrgForbidden {
		t.Fatalf("member must not change roles, got %v", err)
	}
	if err := memberRoleDecision("admin", "support", "", 1); err != nil {
		t.Fatalf("admin should remove a non-admin member: %v", err)
	}
}

func TestOrgRolePattern(t *testing.T) {
	if !orgRolePattern.MatchString("recruiter") || !orgRolePattern.MatchString("admin") {
		t.Fatal("expected valid slugs")
	}
	if orgRolePattern.MatchString("team member") || orgRolePattern.MatchString("Owner") {
		t.Fatal("spaces and capitals are not org role slugs")
	}
}
