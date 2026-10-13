-- PKCE binding for the magic-link code flow (Auth DB). The S256 code_challenge
-- supplied when the link is requested is stored with the token and copied to the
-- one-time code; the exchange must present the matching code_verifier.

BEGIN;

ALTER TABLE magic_link_tokens ADD COLUMN IF NOT EXISTS code_challenge VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE magic_link_codes ADD COLUMN IF NOT EXISTS code_challenge VARCHAR(64) NOT NULL DEFAULT '';

COMMIT;
