-- Revert to original broad permissions
UPDATE admins SET permissions = 'gui_read,gui_write,webhook_access' WHERE username = 'admin';
