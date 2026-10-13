BEGIN;

ALTER TABLE magic_link_codes DROP COLUMN IF EXISTS code_challenge;
ALTER TABLE magic_link_tokens DROP COLUMN IF EXISTS code_challenge;

COMMIT;
