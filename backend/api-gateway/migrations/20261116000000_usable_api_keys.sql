-- API keys are now looked up by SHA-256 (see middleware/api_key.rs).
--
-- Keys made before this were stored as bcrypt hashes, which can't be looked
-- up, and no route ever accepted them, so none of them ever worked. They are
-- retired so the key list shows them as inactive instead of pretending.
UPDATE api_keys SET is_active = FALSE WHERE key_hash LIKE '$2%';

-- The first characters of each key, kept so owners can tell keys apart.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(16);

-- New keys default to reading and scanning (the handler always sets them).
ALTER TABLE api_keys ALTER COLUMN permissions SET DEFAULT ARRAY['read', 'scan'];
