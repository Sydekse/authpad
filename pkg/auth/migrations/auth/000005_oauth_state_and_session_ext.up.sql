-- One-time OAuth state and session extensions (MFA pending, active org)

BEGIN;

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_pending BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_organization_id UUID;

CREATE INDEX IF NOT EXISTS idx_sessions_active_org ON sessions(active_organization_id);

CREATE TABLE IF NOT EXISTS oauth_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_hash TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);

COMMIT;
