BEGIN;

ALTER TABLE organization_invitations DROP COLUMN IF EXISTS payload;
ALTER TABLE organization_memberships DROP COLUMN IF EXISTS level_id;
ALTER TABLE organization_memberships DROP COLUMN IF EXISTS department_id;
DROP TABLE IF EXISTS organization_levels;
DROP TABLE IF EXISTS organization_departments;
DROP TABLE IF EXISTS organization_roles;

COMMIT;
