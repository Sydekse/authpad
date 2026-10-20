package service

import (
	"strings"
	"testing"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
)

var earapaBrand = apptypes.EmailBrand{
	HeaderColor:     "#1E398A",
	ButtonColor:     "#0f1f4d",
	LogoURL:         "https://app.example.com/email/logo.png",
	FontFamily:      "Inter, -apple-system, 'Segoe UI', Arial, sans-serif",
	FooterText:      "Sent by {app}, East African Regulatory Affairs Professionals Association",
	OrgInviteTitle:  "You've been invited to set up the {org} booth on {app}",
	OrgInviteBody:   "Set a password to join the {org} team and open your booth editor.",
	OrgInviteButton: "Set up your booth",
}

func TestOrgInvitationNamesOrgNotRole(t *testing.T) {
	now := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	b := resolveBrand("EARAPA", earapaBrand)
	subject, htmlBody, text := renderOrgInvitation(b, apptypes.OrgInvitationEmail{
		To: "boss@example.com", InviteURL: "https://app.example.com/invite/accept?token=abc%3D", OrgName: "Kestrel & Co", Role: "admin", ExpiresAt: now.Add(72 * time.Hour),
	}, now)
	if subject != "You've been invited to set up the Kestrel & Co booth on EARAPA" {
		t.Fatalf("subject = %q", subject)
	}
	for _, body := range []string{htmlBody, text} {
		if strings.Contains(strings.ToLower(body), "admin") {
			t.Fatal("the internal role must not appear in the email")
		}
		if !strings.Contains(body, "expires in 3 days") {
			t.Fatal("expiry missing")
		}
		if !strings.Contains(body, "Sent by EARAPA, East African Regulatory Affairs Professionals Association") {
			t.Fatal("footer missing")
		}
	}
	if !strings.Contains(htmlBody, "Kestrel &amp; Co") || strings.Contains(htmlBody, "Kestrel & Co") {
		t.Fatal("org name must be HTML-escaped")
	}
	if !strings.Contains(text, "https://app.example.com/invite/accept?token=abc%3D") || !strings.Contains(htmlBody, `href="https://app.example.com/invite/accept?token=abc%3D"`) {
		t.Fatal("invite link missing")
	}
	for _, want := range []string{"#1e398a", "#0f1f4d", `src="https://app.example.com/email/logo.png"`, `alt="EARAPA"`, "Set up your booth", "Inter, -apple-system"} {
		if !strings.Contains(htmlBody, want) {
			t.Fatalf("html missing %q", want)
		}
	}
}

type capturedMail struct{ to, subject, html, text string }

func capturingService(cfg apptypes.EmailConfig) (*EmailService, *[]capturedMail) {
	var out []capturedMail
	s := &EmailService{cfg: cfg, deliver: func(to, subject, h, x string) error {
		out = append(out, capturedMail{to, subject, h, x})
		return nil
	}}
	return s, &out
}

func TestEveryEmailUsesTheSharedLayout(t *testing.T) {
	for _, brand := range []apptypes.EmailBrand{{}, earapaBrand} {
		s, out := capturingService(apptypes.EmailConfig{AppName: "Acme", Brand: brand})
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(s.SendPasswordReset("a@x.test", "https://x.test/reset?token=a%3D"))
		must(s.SendEmailVerification("a@x.test", "https://x.test/verify?token=a%3D"))
		must(s.SendInvitation("a@x.test", "https://x.test/invite?token=a%3D", "admin"))
		must(s.SendOrgInvitation(apptypes.OrgInvitationEmail{To: "a@x.test", InviteURL: "https://x.test/invite?token=a%3D", OrgName: "Org", Role: "admin", ExpiresAt: time.Now().Add(72 * time.Hour)}))
		subject, h, x := magicLinkMail(resolveBrand("Acme", brand), "https://x.test/magic?token=a%3D", 15*time.Minute)
		*out = append(*out, capturedMail{"a@x.test", subject, h, x})
		if len(*out) != 5 {
			t.Fatalf("sent %d emails", len(*out))
		}
		for _, m := range *out {
			for _, body := range []string{m.subject, m.html, m.text} {
				for _, banned := range []string{"\u2014", "\u2013", "Sydek", "Identity", "&copy;", "admin"} {
					if strings.Contains(body, banned) {
						t.Fatalf("%q contains %q", m.subject, banned)
					}
				}
			}
			for _, want := range []string{`content="light dark"`, "prefers-color-scheme: dark", `role="presentation"`, "token=a%3D"} {
				if !strings.Contains(m.html, want) {
					t.Fatalf("%q html missing %q", m.subject, want)
				}
			}
			if !strings.Contains(m.text, "token=a%3D") || strings.Contains(m.text, "<") {
				t.Fatalf("%q plain-text alternative is wrong", m.subject)
			}
		}
		if brand == (apptypes.EmailBrand{}) && !strings.Contains((*out)[0].html, "Sent by Acme.") {
			t.Fatal("default footer missing")
		}
	}
}

func TestBrandRejectsUnsafeValues(t *testing.T) {
	b := resolveBrand("", apptypes.EmailBrand{
		HeaderColor: "red;background:url(x)", ButtonColor: "#12345", LogoURL: "javascript:alert(1)",
		FontFamily: "x;}</style><script>", LogoWidth: 9000,
	})
	if b.App != "Auth" || b.HeaderColor != defaultHeaderColor || b.ButtonColor != defaultButtonColor || b.LogoURL != "" || b.Font != defaultFontFamily || b.LogoWidth != 300 {
		t.Fatalf("unsafe brand values leaked: %+v", b)
	}
	if got := resolveBrand("A", apptypes.EmailBrand{LogoURL: "http://insecure.test/l.png"}).LogoURL; got != "" {
		t.Fatalf("http logo accepted: %q", got)
	}
	if got := resolveBrand("A", apptypes.EmailBrand{FontFamily: `"Inter Tight", Arial`}).Font; got != "'Inter Tight', Arial" {
		t.Fatalf("font = %q", got)
	}
}

func TestExpiresIn(t *testing.T) {
	now := time.Now()
	cases := map[time.Duration]string{72 * time.Hour: "3 days", 7 * 24 * time.Hour: "7 days", 24 * time.Hour: "24 hours", 2 * time.Hour: "2 hours", 30 * time.Minute: "30 minutes", time.Minute: "1 minute", -time.Minute: ""}
	for d, want := range cases {
		if got := expiresIn(now.Add(d), now); got != want {
			t.Fatalf("%v: got %q want %q", d, got, want)
		}
	}
	if expiresIn(time.Time{}, now) != "" {
		t.Fatal("zero time should give no expiry")
	}
}

func TestLinksEscapeTokenPadding(t *testing.T) {
	pages := apptypes.PagesConfig{ResetPasswordURL: "https://app.example.com/reset"}
	if got := BuildResetURL(pages, "ab+c/="); got != "https://app.example.com/reset?token=ab%2Bc%2F%3D" {
		t.Fatalf("reset = %q", got)
	}
}

func TestEveryInterpolatedValueIsEscaped(t *testing.T) {
	b := resolveBrand(`Acme "<b>`, apptypes.EmailBrand{
		LogoURL:    `https://cdn.example.com/l.png?a="><script>`,
		FooterText: `Sent by <i>{app}</i> & "friends"`,
	})
	h, x := renderMail(b, mailContent{Preview: "<p>", Title: "<t>", Intro: "<i>", ActionURL: `https://x.test/?a="><b>`, ActionLabel: "<l>", Note: "<n>"})
	for _, raw := range []string{"<script>", "<b>", "<i>", "<t>", "<l>", "<n>", `a="><`} {
		if strings.Contains(h, raw) {
			t.Fatalf("html contains unescaped %q", raw)
		}
	}
	for _, want := range []string{`alt="Acme &#34;&lt;b&gt;"`, "Sent by &lt;i&gt;Acme &#34;&lt;b&gt;&lt;/i&gt; &amp; &#34;friends&#34;", `src="https://cdn.example.com/l.png?a=&#34;&gt;&lt;script&gt;"`} {
		if !strings.Contains(h, want) {
			t.Fatalf("html missing %q", want)
		}
	}
	if !strings.Contains(x, `Sent by <i>Acme "<b></i> & "friends"`) {
		t.Fatal("plain text should carry the footer verbatim")
	}
}

func TestQuotedLifetimesFollowTheTTLs(t *testing.T) {
	s, out := capturingService(apptypes.EmailConfig{AppName: "Acme"})
	_ = s.SendPasswordReset("a@x.test", "https://x.test/r")
	_ = s.SendEmailVerification("a@x.test", "https://x.test/v")
	if !strings.Contains((*out)[0].text, "expires in "+lifetime(PasswordResetTTL)+".") || lifetime(PasswordResetTTL) != "5 minutes" {
		t.Fatal("reset email must quote the reset TTL")
	}
	if !strings.Contains((*out)[1].text, "expires in 24 hours.") {
		t.Fatal("verification email must quote the verification TTL")
	}
	_, _, x := magicLinkMail(resolveBrand("Acme", apptypes.EmailBrand{}), "https://x.test/m", 15*time.Minute)
	if !strings.Contains(x, "expires in 15 minutes.") {
		t.Fatal("magic link must quote its TTL")
	}
	_, _, x = magicLinkMail(resolveBrand("Acme", apptypes.EmailBrand{}), "https://x.test/m", 0)
	if !strings.Contains(x, "expires soon.") {
		t.Fatal("unknown magic link TTL")
	}
}

func TestLogoHeightIsOptionalAndClamped(t *testing.T) {
	h, _ := renderMail(resolveBrand("A", apptypes.EmailBrand{LogoURL: "https://x.test/l.png", LogoHeight: 26}), mailContent{Title: "t"})
	if !strings.Contains(h, `width="132" height="26"`) || !strings.Contains(h, "height:26px;") {
		t.Fatal("logo height not applied")
	}
	h, _ = renderMail(resolveBrand("A", apptypes.EmailBrand{LogoURL: "https://x.test/l.png"}), mailContent{Title: "t"})
	if strings.Contains(h, `height="`) || !strings.Contains(h, "height:auto;") {
		t.Fatal("logo height should be omitted by default")
	}
	if resolveBrand("A", apptypes.EmailBrand{LogoHeight: 5000}).LogoHeight != 120 {
		t.Fatal("logo height not clamped")
	}
}

func TestOrgNameIsOneShortLine(t *testing.T) {
	long := strings.Repeat("A", 200)
	if got := cleanOrgName("  Kestrel\n\tLabs\r\nYour account is locked "); got != "Kestrel Labs Your account is locked" {
		t.Fatalf("got %q", got)
	}
	got := cleanOrgName(long)
	if r := []rune(got); len(r) != maxOrgNameInEmail || !strings.HasSuffix(got, "\u2026") {
		t.Fatalf("not capped: %d", len(r))
	}
	subject, _, _ := renderOrgInvitation(resolveBrand("A", apptypes.EmailBrand{}), apptypes.OrgInvitationEmail{OrgName: "X\nY", InviteURL: "https://x.test"}, time.Now())
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatal("newline in subject")
	}
}

func TestPlainTextNeverMentionsAButton(t *testing.T) {
	s, out := capturingService(apptypes.EmailConfig{AppName: "Acme"})
	_ = s.SendPasswordReset("a@x.test", "https://x.test/r")
	_ = s.SendEmailVerification("a@x.test", "https://x.test/v")
	_ = s.SendInvitation("a@x.test", "https://x.test/i", "")
	_ = s.SendOrgInvitation(apptypes.OrgInvitationEmail{OrgName: "O", InviteURL: "https://x.test/o"})
	_, _, x := magicLinkMail(resolveBrand("Acme", apptypes.EmailBrand{}), "https://x.test/m", 0)
	*out = append(*out, capturedMail{text: x})
	for _, m := range *out {
		if strings.Contains(strings.ToLower(m.text), "button") {
			t.Fatalf("plain text mentions a button: %q", m.text)
		}
	}
	if magicTTL(0) != DefaultMagicLinkTTL {
		t.Fatal("magic TTL fallback")
	}
}
