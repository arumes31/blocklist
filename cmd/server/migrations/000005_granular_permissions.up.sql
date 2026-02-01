-- Add permissions column to admins table
ALTER TABLE admins ADD COLUMN IF NOT EXISTS permissions TEXT DEFAULT 'gui_read';

-- Set default permissions for existing admin user
UPDATE admins SET permissions = 'gui_read,gui_write,webhook_access' WHERE username = 'admin';
