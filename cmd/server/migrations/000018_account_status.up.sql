-- Additive: existing local and Entra accounts remain enabled.
ALTER TABLE admins ADD COLUMN disabled BOOLEAN NOT NULL DEFAULT FALSE;
