BEGIN;

DROP TABLE IF EXISTS oauth_states;

DROP INDEX IF EXISTS idx_sessions_active_org;
ALTER TABLE sessions DROP COLUMN IF EXISTS active_organization_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS mfa_pending;

COMMIT;
