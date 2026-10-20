package service

import (
	"fmt"
	"html"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Sydekse/authpad/internal/apptypes"
)

// Neutral palette shared by every deployment. Brand colours, logo, fonts and
// footer come from apptypes.EmailBrand.
const (
	mailCanvas   = "#f4f6fa"
	mailPaper    = "#ffffff"
	mailInk      = "#0b1b2e"
	mailMuted    = "#566577"
	mailHairline = "#dce1e6"

	defaultHeaderColor = "#1f2937"
	defaultButtonColor = "#111827"
	defaultFontFamily  = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
	defaultLogoWidth   = 132

	defaultOrgInviteTitle  = "You've been invited to join {org} on {app}"
	defaultOrgInviteBody   = "Accept the invite to join the {org} team on {app}."
	defaultOrgInviteButton = "Accept invite"
)

var (
	hexColorRe   = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	fontFamilyRe = regexp.MustCompile(`^[A-Za-z0-9 ,'"\-]+$`)
)

// mailBrand is apptypes.EmailBrand resolved and made safe to drop into HTML.
type mailBrand struct {
	App          string
	HeaderColor  string
	ButtonColor  string
	LogoURL      string
	LogoWidth    int
	LogoHeight   int
	Font         string
	HeadingFont  string
	Footer       string
	InviteTitle  string
	InviteBody   string
	InviteButton string
}

func resolveBrand(appName string, b apptypes.EmailBrand) mailBrand {
	app := strings.TrimSpace(appName)
	if app == "" {
		app = "Auth"
	}
	font := safeFont(b.FontFamily, defaultFontFamily)
	width := b.LogoWidth
	if width <= 0 {
		width = defaultLogoWidth
	}
	if width < 40 {
		width = 40
	}
	if width > 300 {
		width = 300
	}
	mb := mailBrand{
		App:          app,
		HeaderColor:  safeColor(b.HeaderColor, defaultHeaderColor),
		ButtonColor:  safeColor(b.ButtonColor, defaultButtonColor),
		LogoURL:      safeLogoURL(b.LogoURL),
		LogoWidth:    width,
		LogoHeight:   clampOptional(b.LogoHeight, 12, 120),
		Font:         font,
		HeadingFont:  safeFont(b.HeadingFontFamily, font),
		Footer:       orDefault(b.FooterText, "Sent by {app}."),
		InviteTitle:  orDefault(b.OrgInviteTitle, defaultOrgInviteTitle),
		InviteBody:   orDefault(b.OrgInviteBody, defaultOrgInviteBody),
		InviteButton: orDefault(b.OrgInviteButton, defaultOrgInviteButton),
	}
	mb.Footer = mb.fill(mb.Footer, "")
	return mb
}

func clampOptional(v, lo, hi int) int {
	if v <= 0 {
		return 0
	}
	return max(lo, min(hi, v))
}

func orDefault(v, def string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return def
}

func safeColor(v, def string) string {
	v = strings.TrimSpace(v)
	if hexColorRe.MatchString(v) {
		return strings.ToLower(v)
	}
	return def
}

// safeFont keeps a CSS font stack that cannot leave the style attribute.
func safeFont(v, def string) string {
	v = strings.TrimSpace(v)
	if v == "" || !fontFamilyRe.MatchString(v) {
		return def
	}
	return strings.ReplaceAll(v, `"`, "'")
}

// safeLogoURL accepts absolute https URLs only; email clients block the rest.
func safeLogoURL(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return u.String()
}

// fill replaces {app} and {org} in brand copy.
func (b mailBrand) fill(s, org string) string {
	return strings.NewReplacer("{app}", b.App, "{org}", org).Replace(s)
}

// expiresIn words the time left on a link: "3 days", "24 hours", "45 minutes".
func expiresIn(at, now time.Time) string {
	d := at.Sub(now)
	if at.IsZero() || d <= 0 {
		return ""
	}
	if d >= 48*time.Hour {
		return plural(int(math.Round(d.Hours()/24)), "day")
	}
	if d >= 90*time.Minute {
		return plural(int(math.Round(d.Hours())), "hour")
	}
	return plural(int(math.Max(1, math.Round(d.Minutes()))), "minute")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

type mailContent struct {
	Preview     string
	Title       string
	Intro       string
	ActionURL   string
	ActionLabel string
	Note        string
}

// renderMail builds the HTML and plain-text bodies of one transactional email.
// Table layout with inline styles for Gmail and Outlook. The <style> blocks
// only add the mobile and dark-mode refinements that clients which honour them
// apply; mso conditionals pin the width and font in classic Outlook.
func renderMail(b mailBrand, c mailContent) (htmlBody, textBody string) {
	e := html.EscapeString
	font := b.Font
	heading := b.HeadingFont

	header := fmt.Sprintf(`<span style="font-family:%s;font-size:20px;font-weight:700;letter-spacing:-0.01em;line-height:1.2;color:#ffffff;">%s</span>`, heading, e(b.App))
	if b.LogoURL != "" {
		height, heightCSS := "", "height:auto;"
		if b.LogoHeight > 0 {
			height = fmt.Sprintf(` height="%d"`, b.LogoHeight)
			heightCSS = fmt.Sprintf("height:%dpx;", b.LogoHeight)
		}
		header = fmt.Sprintf(`<img src="%s" width="%d"%s alt="%s" style="display:block;width:%dpx;max-width:100%%;%sborder:0;outline:none;text-decoration:none;font-family:%s;font-size:20px;font-weight:700;line-height:1.2;color:#ffffff;" />`,
			e(b.LogoURL), b.LogoWidth, height, e(b.App), b.LogoWidth, heightCSS, heading)
	}

	cta := ""
	if c.ActionURL != "" && c.ActionLabel != "" {
		href := e(c.ActionURL)
		// Border-built button: the whole pill is clickable in every client,
		// including classic Outlook, which ignores padding on links.
		cta = fmt.Sprintf(`
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0 0;">
                      <tr>
                        <td class="ap-btn" align="center" bgcolor="%[1]s" style="border-radius:999px;background-color:%[1]s;">
                          <a class="ap-btn-a" href="%[2]s" target="_blank" rel="noopener noreferrer" style="display:inline-block;border:14px solid %[1]s;border-left-width:28px;border-right-width:28px;border-radius:999px;background-color:%[1]s;font-family:%[3]s;font-size:16px;font-weight:600;line-height:20px;color:#ffffff;text-decoration:none;mso-padding-alt:0;">%[4]s</a>
                        </td>
                      </tr>
                    </table>
                    <p class="ap-muted" style="margin:24px 0 6px;font-family:%[3]s;font-size:13px;line-height:1.5;color:%[5]s;">If the button doesn't work, copy this link into your browser:</p>
                    <p style="margin:0;font-family:%[3]s;font-size:13px;line-height:1.5;word-break:break-all;"><a class="ap-link" href="%[2]s" target="_blank" rel="noopener noreferrer" style="color:%[6]s;text-decoration:underline;">%[2]s</a></p>`,
			b.ButtonColor, href, font, e(c.ActionLabel), mailMuted, b.HeaderColor)
	}

	note := ""
	if s := strings.TrimSpace(c.Note); s != "" {
		note = fmt.Sprintf(`
                    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0 0;">
                      <tr><td class="ap-rule" style="border-top:1px solid %s;font-size:0;line-height:0;height:1px;">&nbsp;</td></tr>
                    </table>
                    <p class="ap-muted" style="margin:20px 0 0;font-family:%s;font-size:14px;line-height:1.6;color:%s;">%s</p>`, mailHairline, font, mailMuted, e(s))
	}

	// On a dark card the brand's dark button would vanish, so dark mode fills
	// it with the header colour and rings it.
	darkCSS := fmt.Sprintf(`
    @media (prefers-color-scheme: dark) {
      .ap-canvas { background-color: #0b1220 !important; }
      .ap-card { background-color: #131c2e !important; border-color: #273349 !important; }
      .ap-ink { color: #eef2f8 !important; }
      .ap-muted { color: #a9b4c4 !important; }
      .ap-link { color: #a8c1ff !important; }
      .ap-rule { border-color: #273349 !important; }
      .ap-btn { background-color: %[1]s !important; box-shadow: 0 0 0 1px #7d97dc !important; }
      .ap-btn-a { background-color: %[1]s !important; border-color: %[1]s !important; }
    }
    [data-ogsc] .ap-ink { color: #eef2f8 !important; }
    [data-ogsc] .ap-muted { color: #a9b4c4 !important; }
    [data-ogsc] .ap-link { color: #a8c1ff !important; }
    [data-ogsb] .ap-canvas { background-color: #0b1220 !important; }
    [data-ogsb] .ap-card { background-color: #131c2e !important; }
    [data-ogsb] .ap-btn, [data-ogsb] .ap-btn-a { background-color: %[1]s !important; border-color: %[1]s !important; }`, b.HeaderColor)

	htmlBody = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="x-apple-disable-message-reformatting" />
  <meta name="color-scheme" content="light dark" />
  <meta name="supported-color-schemes" content="light dark" />
  <title>%[1]s</title>
  <!--[if mso]><style>body, table, td, a, h1, p, span { font-family: Arial, Helvetica, sans-serif !important; }</style><![endif]-->
  <style>
    :root { color-scheme: light dark; supported-color-schemes: light dark; }
    body { margin: 0; padding: 0; width: 100%% !important; -webkit-text-size-adjust: 100%%; }
    @media (max-width: 600px) {
      .ap-outer { padding: 20px 12px !important; }
      .ap-band { padding: 20px 24px !important; }
      .ap-body { padding: 28px 24px 28px !important; }
      .ap-h1 { font-size: 24px !important; }
    }
  </style>
  <style>%[2]s
  </style>
</head>
<body class="ap-canvas" style="margin:0;padding:0;background-color:%[3]s;">
  <div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px;color:%[3]s;">%[4]s&#8199;&#847;&#8199;&#847;&#8199;&#847;&#8199;&#847;&#8199;&#847;&#8199;&#847;</div>
  <div role="article" aria-roledescription="email" aria-label="%[1]s" lang="en">
  <table class="ap-canvas" role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" bgcolor="%[3]s" style="background-color:%[3]s;">
    <tr>
      <td class="ap-outer" align="center" style="padding:40px 16px;">
        <!--[if mso]><table role="presentation" width="560" align="center" cellspacing="0" cellpadding="0" border="0"><tr><td><![endif]-->
        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%%;">
          <tr>
            <td class="ap-card" bgcolor="%[5]s" style="background-color:%[5]s;border:1px solid %[6]s;border-radius:16px;overflow:hidden;">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td class="ap-band" bgcolor="%[7]s" style="background-color:%[7]s;padding:24px 36px;border-radius:15px 15px 0 0;">%[8]s</td>
                </tr>
                <tr>
                  <td class="ap-body" style="padding:36px 36px 32px;">
                    <h1 class="ap-ink ap-h1" style="margin:0 0 14px;font-family:%[9]s;font-size:26px;font-weight:700;letter-spacing:-0.01em;line-height:1.25;color:%[10]s;">%[1]s</h1>
                    <p class="ap-ink" style="margin:0;font-family:%[11]s;font-size:16px;line-height:1.6;color:%[10]s;">%[12]s</p>%[13]s%[14]s
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td class="ap-muted" align="center" style="padding:24px 16px 0;font-family:%[11]s;font-size:13px;line-height:1.6;color:%[15]s;">%[16]s</td>
          </tr>
        </table>
        <!--[if mso]></td></tr></table><![endif]-->
      </td>
    </tr>
  </table>
  </div>
</body>
</html>`,
		e(c.Title), darkCSS, mailCanvas, e(c.Preview),
		mailPaper, mailHairline, b.HeaderColor, header,
		heading, mailInk, font, e(c.Intro), cta, note,
		mailMuted, e(b.Footer),
	)

	var t strings.Builder
	t.WriteString(c.Title + "\n\n" + c.Intro + "\n")
	if c.ActionURL != "" {
		t.WriteString("\n" + c.ActionLabel + ":\n" + c.ActionURL + "\n")
	}
	if c.Note != "" {
		t.WriteString("\n" + c.Note + "\n")
	}
	t.WriteString("\n-- \n" + b.Footer + "\n")
	return htmlBody, t.String()
}
