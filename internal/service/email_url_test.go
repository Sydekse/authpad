package service

import (
	"testing"

	"github.com/Sydekse/authpad/internal/apptypes"
)

func TestBuildVerifyAndResetURL(t *testing.T) {
	pages := apptypes.PagesConfig{
		VerifyEmailURL:   "https://app.example.com/verify",
		ResetPasswordURL: "https://app.example.com/reset?src=mail",
	}
	if got := BuildVerifyURL(pages, "tok"); got != "https://app.example.com/verify?token=tok" {
		t.Fatalf("verify = %q", got)
	}
	if got := BuildResetURL(pages, "tok"); got != "https://app.example.com/reset?src=mail&token=tok" {
		t.Fatalf("reset = %q", got)
	}
	if got := BuildVerifyURL(apptypes.PagesConfig{}, "tok"); got != "/verify-email?token=tok" {
		t.Fatalf("fallback verify = %q", got)
	}
}
