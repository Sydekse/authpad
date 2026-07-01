-- MFA recovery codes (Auth DB)

BEGIN;

ALTER TABLE factors ADD COLUMN IF NOT EXISTS label VARCHAR(255);
ALTER TABLE factors ADD COLUMN IF NOT EXISTS credential_id TEXT;
ALTER TABLE factors ADD COLUMN IF NOT EXISTS public_key TEXT;
ALTER TABLE factors ADD COLUMN IF NOT EXISTS sign_count BIGINT DEFAULT 0;

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users_auth(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);

COMMIT;
