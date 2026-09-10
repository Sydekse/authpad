-- Generic invitations and optional company tenancy (IdP DB)

BEGIN;

CREATE TABLE IF NOT EXISTS invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50),
    payload JSONB NOT NULL DEFAULT '{}',
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    invited_by UUID,
    redeemed_at TIMESTAMPTZ,
    redeemed_user_id UUID,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(63) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    image_url TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

CREATE TABLE IF NOT EXISTS organization_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON organization_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON organization_memberships(organization_id);

CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    invited_by UUID,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org ON organization_invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON organization_invitations(email);
CREATE INDEX IF NOT EXISTS idx_org_invitations_token ON organization_invitations(token_hash);

COMMIT;
