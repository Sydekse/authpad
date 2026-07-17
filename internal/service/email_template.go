package service

import (
	"fmt"
	"html"
	"strings"
)

// Sydek-aligned email tokens (shared visual language with Sydek Auth).
const (
	mailCanvas   = "#f5f5f5"
	mailPaper    = "#ffffff"
	mailInk      = "#0a0a0a"
	mailInkSoft  = "#171717"
	mailMidGray  = "#737373"
	mailHairline = "#e5e5e5"
	mailEmber    = "#e7000b"
)

type mailContent struct {
	Preview     string
	Eyebrow     string
	Title       string
	Intro       string
	ActionURL   string
	ActionLabel string
	Note        string
}

func renderSydekMail(appName string, c mailContent) (htmlBody, textBody string) {
	app := html.EscapeString(strings.TrimSpace(appName))
	if app == "" {
		app = "Sydek Auth"
	}
	preview := html.EscapeString(c.Preview)
	eyebrow := html.EscapeString(strings.ToUpper(strings.TrimSpace(c.Eyebrow)))
	title := html.EscapeString(c.Title)
	intro := html.EscapeString(c.Intro)
	note := html.EscapeString(c.Note)
	actionURL := html.EscapeString(c.ActionURL)
	actionLabel := html.EscapeString(c.ActionLabel)

	eyebrowBlock := ""
	if eyebrow != "" {
		eyebrowBlock = fmt.Sprintf(`
              <p style="margin:0 0 10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:11px;font-weight:500;letter-spacing:0.14em;line-height:1.3;color:%s;text-transform:uppercase;">%s</p>`, mailMidGray, eyebrow)
	}
	ctaBlock := ""
	if c.ActionURL != "" && c.ActionLabel != "" {
		ctaBlock = fmt.Sprintf(`
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:28px 0 8px;">
                <tr>
                  <td style="border-radius:18px;background-color:%s;">
                    <a href="%s" target="_blank" rel="noopener noreferrer"
                       style="display:inline-block;padding:12px 22px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;font-weight:500;line-height:1.2;color:#fafafa;text-decoration:none;border-radius:18px;">%s</a>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.5;color:%s;">Or paste this link into your browser:</p>
              <p style="margin:0 0 8px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;line-height:1.5;word-break:break-all;">
                <a href="%s" style="color:%s;text-decoration:underline;">%s</a>
              </p>`, mailInk, actionURL, actionLabel, mailMidGray, actionURL, mailMidGray, actionURL)
	}
	noteBlock := ""
	if note != "" {
		noteBlock = fmt.Sprintf(`
              <p style="margin:20px 0 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.5;color:%s;">%s</p>`, mailMidGray, note)
	}

	htmlBody = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="light" />
  <title>%s</title>
</head>
<body style="margin:0;padding:0;background-color:%s;-webkit-font-smoothing:antialiased;">
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">%s</div>
  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="background-color:%s;">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;width:100%%;">
          <tr>
            <td style="padding:0 4px 20px;">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;font-weight:600;letter-spacing:-0.02em;color:%s;">%s</td>
                  <td align="right" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;color:%s;">Identity</td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color:%s;border:1px solid %s;border-radius:24px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                <tr><td style="height:3px;line-height:3px;font-size:0;background-color:%s;">&nbsp;</td></tr>
                <tr>
                  <td style="padding:32px 28px 28px;">
                    %s
                    <h1 style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:24px;font-weight:600;letter-spacing:-0.03em;line-height:1.25;color:%s;">%s</h1>
                    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:%s;">%s</p>
                    %s
                    %s
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:24px 8px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:%s;text-align:center;">
              <p style="margin:0 0 6px;">This message was sent by %s. If you did not expect it, you can ignore it safely.</p>
              <p style="margin:0;">&copy; Sydek. All rights reserved.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`,
		title, mailCanvas, preview, mailCanvas, mailInk, app, mailMidGray,
		mailPaper, mailHairline, mailEmber, eyebrowBlock, mailInk, title,
		mailInkSoft, intro, ctaBlock, noteBlock, mailMidGray, app,
	)

	var text strings.Builder
	text.WriteString(c.Title)
	text.WriteString("\n\n")
	text.WriteString(c.Intro)
	text.WriteString("\n")
	if c.ActionURL != "" {
		text.WriteString("\n")
		text.WriteString(c.ActionLabel)
		text.WriteString(": ")
		text.WriteString(c.ActionURL)
		text.WriteString("\n")
	}
	if c.Note != "" {
		text.WriteString("\n")
		text.WriteString(c.Note)
		text.WriteString("\n")
	}
	text.WriteString("\n—\n")
	name := strings.TrimSpace(appName)
	if name == "" {
		name = "Sydek Auth"
	}
	text.WriteString(name)
	text.WriteString("\n")
	textBody = text.String()
	return htmlBody, textBody
}
