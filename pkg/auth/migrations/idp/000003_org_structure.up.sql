-- Per-organization roles, departments, and levels.

BEGIN;

CREATE TABLE IF NOT EXISTS organization_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_org_roles_org ON organization_roles(organization_id);

CREATE TABLE IF NOT EXISTS organization_departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_org_departments_org ON organization_departments(organization_id);

CREATE TABLE IF NOT EXISTS organization_levels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_org_levels_org ON organization_levels(organization_id);

ALTER TABLE organization_memberships
    ADD COLUMN IF NOT EXISTS department_id UUID REFERENCES organization_departments(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS level_id UUID REFERENCES organization_levels(id) ON DELETE SET NULL;

ALTER TABLE organization_invitations
    ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}';

INSERT INTO organization_roles (organization_id, name, description)
SELECT o.id, r.name, r.description
FROM organizations o
CROSS JOIN (VALUES
    ('owner', 'Organization owner'),
    ('admin', 'Organization admin'),
    ('member', 'Organization member')
) AS r(name, description)
ON CONFLICT (organization_id, name) DO NOTHING;

COMMIT;
