-- Remove the manage_excluded permission and clean up separators.
UPDATE admins
SET permissions = (
    SELECT string_agg(p, ',')
    FROM unnest(string_to_array(permissions, ',')) AS p
    WHERE trim(p) <> 'manage_excluded'
)
WHERE permissions LIKE '%manage_excluded%';
