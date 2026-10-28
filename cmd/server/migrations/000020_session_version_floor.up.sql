-- Sessions bind to an account by username and session_version, and a session is
-- rejected only when the stored version is greater than the session's. A deleted
-- and recreated username would restart at 1 and revive the old account's
-- unexpired sessions, so remember the last version of every deleted username and
-- start any recreated account above it.
CREATE TABLE IF NOT EXISTS admin_session_version_floor (
    username TEXT PRIMARY KEY,
    session_version INT NOT NULL
);

CREATE OR REPLACE FUNCTION admins_record_session_floor() RETURNS trigger AS $$
BEGIN
    INSERT INTO admin_session_version_floor (username, session_version)
    VALUES (OLD.username, OLD.session_version)
    ON CONFLICT (username) DO UPDATE
        SET session_version = GREATEST(admin_session_version_floor.session_version, EXCLUDED.session_version);
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION admins_apply_session_floor() RETURNS trigger AS $$
DECLARE
    floor_version INT;
BEGIN
    SELECT session_version INTO floor_version
    FROM admin_session_version_floor WHERE username = NEW.username;
    IF FOUND AND NEW.session_version <= floor_version THEN
        NEW.session_version := floor_version + 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS admins_session_floor_on_delete ON admins;
CREATE TRIGGER admins_session_floor_on_delete
    AFTER DELETE ON admins
    FOR EACH ROW EXECUTE FUNCTION admins_record_session_floor();

DROP TRIGGER IF EXISTS admins_session_floor_on_insert ON admins;
CREATE TRIGGER admins_session_floor_on_insert
    BEFORE INSERT ON admins
    FOR EACH ROW EXECUTE FUNCTION admins_apply_session_floor();
