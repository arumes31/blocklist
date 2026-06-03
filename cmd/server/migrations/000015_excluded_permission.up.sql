-- Grant the new manage_excluded permission to admins who can already manage the
-- whitelist, so existing administrators keep parity with the new excluded list.
UPDATE admins
SET permissions = permissions || ',manage_excluded'
WHERE permissions LIKE '%manage_whitelist%'
  AND permissions NOT LIKE '%manage_excluded%';
