-- Display names for automatically provisioned Entra accounts. Records keep the
-- immutable entra:<tenant>:<object> key; this table only makes that key readable
-- and outlives account deletion so historical records keep their sign-in name.
-- It is never used for authentication or authorization.
CREATE TABLE IF NOT EXISTS account_labels (
    username TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO account_labels (username, label)
SELECT username, btrim(entra_upn) FROM admins
WHERE auth_source = 'entra' AND username LIKE 'entra:%' AND btrim(entra_upn) <> ''
ON CONFLICT (username) DO NOTHING;
