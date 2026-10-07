-- Rollback removes status enforcement and therefore re-enables disabled accounts.
ALTER TABLE admins DROP COLUMN disabled;
