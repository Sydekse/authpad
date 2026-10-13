-- One-time exchange codes for the magic-link code flow (Auth DB).
-- Only the SHA-256 hash of a code is stored. A code is bound to the session
-- that verify created, the tenant, and the exact redirect origin.

BEGIN;

CREATE TABLE IF NOT EXISTS magic_link_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash VARCHAR(64) NOT NULL,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- Organizations live in the IdP database, so there is no foreign key.
    organization_id UUID NOT NULL,
    redirect_origin TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_magic_link_codes_code_hash ON magic_link_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_magic_link_codes_expires_at ON magic_link_codes(expires_at);

COMMIT;
