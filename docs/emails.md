# Transactional emails

authpad sends five emails through Resend (`RESEND_API_KEY`): organization invites, platform invites, password reset, email verification (sender `RESEND_FROM`) and magic links (sender `MAGIC_LINK_FROM`, falling back to `RESEND_FROM`). They share one layout: a light card on a light canvas, a coloured header band with your logo or app name, one rounded button, the link as plain text under it, and a footer line. Every email has a plain-text alternative. The HTML is table-based with inline styles, and adds mobile and dark-mode refinements for clients that honour `<style>` (Apple Mail, iOS Mail, Outlook.com). Gmail applies its own dark-mode colours.

## Branding

All settings are optional. Empty or invalid values fall back to the neutral defaults.

| Env | Config | Default | Notes |
| --- | --- | --- | --- |
| `APP_NAME` | `Email.AppName` | `Auth` | Used in subjects and copy, and in the band when there is no logo. |
| `EMAIL_HEADER_COLOR` | `Email.Brand.HeaderColor` | `#1f2937` | Header band. Hex only (`#rgb` or `#rrggbb`). |
| `EMAIL_BUTTON_COLOR` | `Email.Brand.ButtonColor` | `#111827` | Button background; button text is white, so pick a dark colour. |
| `EMAIL_LOGO_URL` | `Email.Brand.LogoURL` | none | Absolute `https` URL to a PNG or JPG drawn on the band (use light artwork). SVG does not render in Gmail. Export at 2x or 3x. |
| `EMAIL_LOGO_WIDTH` | `Email.Brand.LogoWidth` | `132` | Display width in CSS pixels, 40 to 300. |
| `EMAIL_LOGO_HEIGHT` | `Email.Brand.LogoHeight` | none | Display height in CSS pixels, 12 to 120. Set it (width times the image's aspect ratio) so the band keeps its height when images are off. |
| `EMAIL_FONT_FAMILY` | `Email.Brand.FontFamily` | system stack | CSS font stack. Web fonts are not loaded, so end it with system fallbacks. Letters, digits, spaces, commas, quotes and hyphens only. |
| `EMAIL_HEADING_FONT_FAMILY` | `Email.Brand.HeadingFontFamily` | `EMAIL_FONT_FAMILY` | Heading and band text. |
| `EMAIL_FOOTER_TEXT` | `Email.Brand.FooterText` | `Sent by {app}.` | Line under the card. |
| `EMAIL_ORG_INVITE_TITLE` | `Email.Brand.OrgInviteTitle` | `You've been invited to join {org} on {app}` | Subject and heading of organization invites. |
| `EMAIL_ORG_INVITE_BODY` | `Email.Brand.OrgInviteBody` | `Accept the invite to join the {org} team on {app}.` | |
| `EMAIL_ORG_INVITE_BUTTON` | `Email.Brand.OrgInviteButton` | `Accept invite` | |

`{app}` is `APP_NAME` and `{org}` is the organization's name. Role names are never shown in emails.

Branding is per authpad process, not per tenant: every organization and tenant served by one instance gets the same look and invite wording. Per-tenant overrides are not supported yet.

The lifetimes quoted in emails come from the code: password reset links last 5 minutes, verification links 24 hours, magic links `MAGIC_LINK_TTL`, and invites `AUTHPAD_INVITE_TTL`.

## Invite links

`POST /admin/invitations` and `POST /organizations/{slug}/invitations` take a `callback_url`; the email links to `<callback_url>?token=...`. Its origin must be allowed, or the request fails with `400 INVALID_CALLBACK_URL` and nothing is sent:

| Env | Config | Default |
| --- | --- | --- |
| `AUTHPAD_INVITE_CALLBACK_ORIGINS` | `Invitations.CallbackOrigins` | `ALLOWED_ORIGINS`, `MAGIC_LINK_REDIRECT_ALLOWLIST` and the origins of the hosted page URLs |

Origins are exact (`scheme://host[:port]`). This stops an organization admin from sending a branded invite, with a live token, that points at another site.

## Custom mailers

A host `Config.Mailer` keeps working unchanged. To get the organization name, expiry and role for organization invites, also implement `auth.OrgInvitationMailer`:

```go
func (m *MyMailer) SendOrgInvitation(msg auth.OrgInvitationEmail) error
```

## Links

Tokens are padded URL-safe base64 and end in `=`. Invite, reset and verification links percent-encode the token (`%3D`), so read it with a normal query parser. The `GET .../invitations/{token}/validate` endpoints accept the token raw or percent-encoded.
