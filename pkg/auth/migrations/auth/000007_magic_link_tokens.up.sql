-- Magic-link sign-in tokens (Auth DB). Only the SHA-256 hash of a token is stored.

BEGIN;

CREATE TABLE IF NOT EXISTS magic_link_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(64) NOT NULL,
    -- Organizations live in the IdP database, so there is no foreign key.
    organization_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    redirect_to TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_magic_link_tokens_token_hash ON magic_link_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_magic_link_tokens_expires_at ON magic_link_tokens(expires_at);

COMMIT;
