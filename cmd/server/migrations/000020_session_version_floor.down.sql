DROP TRIGGER IF EXISTS admins_session_floor_on_insert ON admins;
DROP TRIGGER IF EXISTS admins_session_floor_on_delete ON admins;
DROP FUNCTION IF EXISTS admins_apply_session_floor();
DROP FUNCTION IF EXISTS admins_record_session_floor();
DROP TABLE IF EXISTS admin_session_version_floor;
