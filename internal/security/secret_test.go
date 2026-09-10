package security

import "testing"

func TestEqualSecret(t *testing.T) {
	if !EqualSecret("abc", "abc") {
		t.Fatal("expected match")
	}
	if EqualSecret("abc", "abd") {
		t.Fatal("expected mismatch")
	}
	if EqualSecret("abc", "ab") {
		t.Fatal("expected length mismatch")
	}
	if EqualSecret("", "x") {
		t.Fatal("empty should not match a key")
	}
}
