-- Keep each managed account's effective permissions before removing the catalog.
UPDATE admins a SET permissions = r.permissions, role = r.id
FROM access_roles r WHERE a.role_id = r.id;
DROP INDEX admins_entra_identity_unique;
DROP INDEX admins_role_id_idx;
ALTER TABLE admins DROP CONSTRAINT admins_entra_binding_complete;
ALTER TABLE admins DROP COLUMN entra_role_override;
ALTER TABLE admins DROP COLUMN entra_upn;
ALTER TABLE admins DROP COLUMN entra_object_id;
ALTER TABLE admins DROP COLUMN entra_tenant_id;
ALTER TABLE admins DROP COLUMN auth_source;
ALTER TABLE admins DROP COLUMN role_id;
DROP TABLE access_roles;
